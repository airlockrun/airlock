package agentapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/db/dbq"
	"go.uber.org/zap"
)

// formatRunLogs renders structured log entries into the flat text shape
// stored in runs.stdout_log. Levels above info get a "[level] " prefix so
// the run-detail UI can pick them out without a schema migration.
func formatRunLogs(logs []agentsdk.LogEntry) string {
	if len(logs) == 0 {
		return ""
	}
	parts := make([]string, len(logs))
	for i, l := range logs {
		switch l.Level {
		case agentsdk.LogLevelDebug:
			parts[i] = "[debug] " + l.Message
		case agentsdk.LogLevelWarn:
			parts[i] = "[warn] " + l.Message
		case agentsdk.LogLevelError:
			parts[i] = "[error] " + l.Message
		default:
			parts[i] = l.Message
		}
	}
	return strings.Join(parts, "\n")
}

// RunComplete handles POST /api/agent/run/complete.
func (h *Handler) RunComplete(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())

	var req agentsdk.RunCompleteRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	runUUID, err := parseUUID(req.RunID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid run_id")
		return
	}

	// Run logs are kept for every run (success and failure alike) and
	// rendered in the run-detail UI. agentsdk caps the buffer it sends
	// (~64 KiB) so the row stays bounded; CompactOldRuns nulls stdout_log
	// along with the other verbose fields once the run ages out.
	//
	// agentsdk classifies the error structurally (by call-site, not regex)
	// and sends the kind in req.ErrorKind. We trust it as-is.
	q := dbq.New(h.db.Pool())
	// Authoritative cap on per-action stdout/stderr in the audit log.
	// The SDK already truncates on its side; we re-enforce here so
	// the runs.actions JSONB invariant holds regardless of SDK
	// version or bypass path.
	actions := truncateActionsJSON(req.Actions)
	if err := q.UpsertRunComplete(r.Context(), dbq.UpsertRunCompleteParams{
		ID:           toPgUUID(runUUID),
		AgentID:      toPgUUID(agentID),
		Status:       req.Status,
		ErrorMessage: req.Error,
		ErrorKind:    req.ErrorKind,
		Actions:      actions,
		StdoutLog:    formatRunLogs(req.Logs),
		PanicTrace:   req.PanicTrace,
	}); err != nil {
		h.logger.Error("upsert run complete failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to record run completion")
		return
	}

	// Persist the error as a synthetic assistant message in the conversation
	// (if the run is conversation-attached) so the chat surface keeps the
	// banner after refresh. WS already paints it transiently. Cron- or
	// webhook-triggered runs that never wrote a message return no rows from
	// GetConversationIDByRun and we skip silently.
	if req.Status == "error" && req.Error != "" {
		convID, lookupErr := q.GetConversationIDByRun(r.Context(), toPgUUID(runUUID))
		if lookupErr == nil && convID.Valid {
			if _, err := q.CreateMessage(r.Context(), dbq.CreateMessageParams{
				ConversationID: convID,
				Role:           "assistant",
				Source:         "error",
				Content:        req.Error,
				RunID:          toPgUUID(runUUID),
			}); err != nil {
				h.logger.Warn("persist error message failed", zap.Error(err))
			}
		}
	}

	// Aggregate LLM telemetry (tokens, cost, call count) onto the run row
	// from the llm_usage ledger (the proxy writes one row per model
	// round-trip with cost already computed). Non-fatal — the run is
	// already marked complete; a failed rollup just means the run-list
	// shows zeros until the next idempotent recompute.
	if err := q.UpdateRunLLMStats(r.Context(), toPgUUID(runUUID)); err != nil {
		h.logger.Error("aggregate run llm stats failed", zap.Error(err))
	}

	// Store checkpoint for suspended runs.
	if len(req.Checkpoint) > 0 {
		if err := q.UpdateRunCheckpoint(r.Context(), dbq.UpdateRunCheckpointParams{
			ID:         toPgUUID(runUUID),
			Checkpoint: req.Checkpoint,
		}); err != nil {
			h.logger.Error("store checkpoint failed", zap.Error(err))
		}
	}

	// Tool-call/tool-result pairing invariant: provider APIs reject the next
	// LLM turn if any assistant tool_use isn't followed by a matching
	// tool_result. Cancel, deadline-exceeded, and panic-mid-tool all leave
	// orphans. Synthesize them here so the conversation is safe to feed
	// back to the LLM. SessionLoad has a belt-and-suspenders fallback.
	if req.Status != "success" && req.Status != "suspended" {
		SynthesizeOrphanToolResults(r.Context(), q, runUUID, req.Status, h.logger)
	}

	// Publish terminal WS event so the live UI flips when the streaming
	// /prompt connection died (cancel, network blip, container restart).
	// Duplicates PublishRunEvents in the happy path; the chat store
	// idempotently no-ops the second event for an already-finalized run.
	PublishRunTerminal(r.Context(), h.pubsub, agentID, runUUID, req.Status, req.Error)

	w.WriteHeader(http.StatusOK)
}

// GetCheckpoint handles GET /api/agent/run/{runID}/checkpoint.
func (h *Handler) GetCheckpoint(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUID(r.PathValue("runID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid run_id")
		return
	}

	q := dbq.New(h.db.Pool())
	row, err := q.GetRunCheckpoint(r.Context(), toPgUUID(runID))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "run not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(row)
}

// Upgrade handles POST /api/agent/upgrade.
func (h *Handler) Upgrade(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())

	var req struct {
		Description    string `json:"description"`
		ConversationID string `json:"conversationId"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	input := builder.UpgradeInput{
		AgentID:        agentID.String(),
		Reason:         "llm_request",
		Description:    req.Description,
		ConversationID: req.ConversationID,
	}
	// Attribute the codegen spend to the user in whose conversation the agent
	// requested this upgrade; the builder falls back to the agent owner when
	// no conversation is bound.
	if req.ConversationID != "" {
		if cu, perr := parseUUID(req.ConversationID); perr == nil {
			if conv, cerr := dbq.New(h.db.Pool()).GetConversationByID(r.Context(), toPgUUID(cu)); cerr == nil {
				input.InitiatorUserID = conv.UserID
			}
		}
	}

	if err := h.builder.AcquireUpgradeLock(r.Context(), input.AgentID); err != nil {
		if errors.Is(err, builder.ErrUpgradeInProgress) {
			writeJSONError(w, http.StatusConflict, "upgrade already in progress")
			return
		}
		h.logger.Error("upgrade lock failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to start upgrade")
		return
	}

	go h.builder.RunUpgrade(context.Background(), input)

	w.WriteHeader(http.StatusAccepted)
}
