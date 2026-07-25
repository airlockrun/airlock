package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// formatRunLogs renders structured log entries into the flat text shape
// stored in runs.stdout_log. Levels above info get a "[level] " prefix so
// the run-detail UI can pick them out without a schema migration.
func formatRunLogs(logs []wire.LogEntry) string {
	if len(logs) == 0 {
		return ""
	}
	parts := make([]string, len(logs))
	for i, l := range logs {
		switch l.Level {
		case wire.LogLevelDebug:
			parts[i] = "[debug] " + l.Message
		case wire.LogLevelWarn:
			parts[i] = "[warn] " + l.Message
		case wire.LogLevelError:
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

	var req wire.RunCompleteRequest
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
	//
	// Authoritative cap on per-action stdout/stderr in the audit log.
	// The SDK already truncates on its side; we re-enforce here so
	// the runs.actions JSONB invariant holds regardless of SDK
	// version or bypass path.
	actionsJSON, err := json.Marshal(req.Actions)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid actions")
		return
	}
	actions := truncateActionsJSON(actionsJSON)
	checkpoint := bytes.TrimSpace(req.Checkpoint)
	if req.Status == "suspended" {
		if err := ValidateSuspendedCheckpoint(checkpoint); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// The suspended status and its checkpoint form one resumable state. Keep
	// both writes in one transaction so a concurrent confirmation cannot
	// observe status='suspended' before the checkpoint is available.
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		h.logger.Error("begin run completion transaction failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to record run completion")
		return
	}
	defer tx.Rollback(r.Context())
	qtx := dbq.New(h.db.Pool()).WithTx(tx)
	rows, err := qtx.UpsertRunComplete(r.Context(), dbq.UpsertRunCompleteParams{
		ID:           toPgUUID(runUUID),
		AgentID:      toPgUUID(agentID),
		Status:       req.Status,
		ErrorMessage: req.Error,
		ErrorKind:    req.ErrorKind,
		Actions:      actions,
		StdoutLog:    formatRunLogs(req.Logs),
		PanicTrace:   req.PanicTrace,
		Checkpoint:   checkpoint,
	})
	if err != nil {
		h.logger.Error("upsert run complete failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to record run completion")
		return
	}
	if rows == 0 {
		stored, getErr := qtx.GetRunByIDAndAgent(r.Context(), dbq.GetRunByIDAndAgentParams{
			ID: toPgUUID(runUUID), AgentID: toPgUUID(agentID),
		})
		switch {
		case errors.Is(getErr, pgx.ErrNoRows):
			writeJSONError(w, http.StatusNotFound, "run not found")
		case getErr != nil:
			h.logger.Error("load existing run completion failed", zap.Error(getErr))
			writeJSONError(w, http.StatusInternalServerError, "failed to record run completion")
		case runCompletionMatches(stored, req, actions, checkpoint):
			w.WriteHeader(http.StatusOK)
		default:
			writeJSONError(w, http.StatusConflict, "run already completed")
		}
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("commit run completion transaction failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to record run completion")
		return
	}
	q := dbq.New(h.db.Pool())

	// Aggregate LLM telemetry (tokens, cost, call count) onto the run row
	// from the llm_usage ledger (the proxy writes one row per model
	// round-trip with cost already computed). Non-fatal — the run is
	// already marked complete; a failed rollup just means the run-list
	// shows zeros until the next idempotent recompute.
	if err := q.UpdateRunLLMStats(r.Context(), toPgUUID(runUUID)); err != nil {
		h.logger.Error("aggregate run llm stats failed", zap.Error(err))
	}

	// Tool-call/tool-result pairing invariant: provider APIs reject the next
	// LLM turn if any assistant tool_use isn't followed by a matching
	// tool_result. Cancel, deadline-exceeded, and panic-mid-tool all leave
	// orphans. Synthesize them here so the conversation is safe to feed
	// back to the LLM. SessionLoad has a belt-and-suspenders fallback.
	if req.Status != "success" && req.Status != "suspended" {
		SynthesizeOrphanToolResults(r.Context(), q, runUUID, req.Status, h.logger)
	}

	// Persist the error after orphan synthesis so provider history remains
	// assistant tool-call -> synthetic tool result -> assistant error.
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

	// Publish terminal WS event so the live UI flips when the streaming
	// /prompt connection died (cancel, network blip, container restart).
	// Duplicates PublishRunEvents in the happy path; the chat store
	// idempotently no-ops the second event for an already-finalized run.
	PublishRunTerminal(r.Context(), h.pubsub, agentID, runUUID, req.Status, req.Error)

	w.WriteHeader(http.StatusOK)
}

func runCompletionMatches(run dbq.Run, req wire.RunCompleteRequest, actions, checkpoint []byte) bool {
	return run.Status == req.Status &&
		run.ErrorMessage == req.Error &&
		run.ErrorKind == req.ErrorKind &&
		run.StdoutLog == formatRunLogs(req.Logs) &&
		run.PanicTrace == req.PanicTrace &&
		jsonEqual(run.Actions, actions) &&
		jsonEqual(run.Checkpoint, checkpoint)
}

func jsonEqual(a, b []byte) bool {
	if len(bytes.TrimSpace(a)) == 0 || len(bytes.TrimSpace(b)) == 0 {
		return len(bytes.TrimSpace(a)) == 0 && len(bytes.TrimSpace(b)) == 0
	}
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// GetCheckpoint handles GET /api/agent/run/{runID}/checkpoint.
func (h *Handler) GetCheckpoint(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	runID, err := parseUUID(r.PathValue("runID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid run_id")
		return
	}

	q := dbq.New(h.db.Pool())
	row, err := q.GetRunCheckpoint(r.Context(), dbq.GetRunCheckpointParams{
		ID: toPgUUID(runID), AgentID: toPgUUID(agentID),
	})
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
		cu, err := parseUUID(req.ConversationID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid conversationId")
			return
		}
		conv, err := dbq.New(h.db.Pool()).GetConversationByIDAndAgent(r.Context(), dbq.GetConversationByIDAndAgentParams{
			ID: toPgUUID(cu), AgentID: toPgUUID(agentID),
		})
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "conversation not found")
			return
		}
		input.InitiatorUserID = conv.UserID
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
