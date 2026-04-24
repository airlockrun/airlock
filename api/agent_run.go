package api

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

// RunComplete handles POST /api/agent/run/complete.
func (h *agentHandler) RunComplete(w http.ResponseWriter, r *http.Request) {
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

	q := dbq.New(h.db.Pool())
	if err := q.UpsertRunComplete(r.Context(), dbq.UpsertRunCompleteParams{
		ID:           toPgUUID(runUUID),
		AgentID:      toPgUUID(agentID),
		Status:       req.Status,
		ErrorMessage: req.Error,
		Actions:      req.Actions,
		StdoutLog:    strings.Join(req.Logs, "\n"),
		PanicTrace:   req.PanicTrace,
	}); err != nil {
		h.logger.Error("upsert run complete failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to record run completion")
		return
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

	w.WriteHeader(http.StatusOK)
}

// GetCheckpoint handles GET /api/agent/run/{runID}/checkpoint.
func (h *agentHandler) GetCheckpoint(w http.ResponseWriter, r *http.Request) {
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
func (h *agentHandler) Upgrade(w http.ResponseWriter, r *http.Request) {
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
