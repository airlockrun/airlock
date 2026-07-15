package agentapi

import (
	"net/http"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// CreateScheduledFire handles POST /api/agent/schedules — arm a one-shot fire
// (agent.ScheduleAt). The platform records only when to fire which handler;
// per-instance data lives in the agent's own DB, keyed by the returned fire id.
func (h *Handler) CreateScheduledFire(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())

	var req wire.ScheduleAtRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Slug == "" || req.FireAt.IsZero() {
		writeJSONError(w, http.StatusBadRequest, "slug and fireAt are required")
		return
	}

	q := dbq.New(h.db.Pool())
	handler, err := q.GetScheduleHandler(r.Context(), dbq.GetScheduleHandlerParams{
		AgentID: toPgUUID(agentID),
		Slug:    req.Slug,
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "no registered schedule handler: "+req.Slug)
		return
	}

	id, err := q.InsertScheduledFire(r.Context(), dbq.InsertScheduledFireParams{
		AgentID:    toPgUUID(agentID),
		Source:     "schedule",
		Slug:       req.Slug,
		FireAt:     pgtype.Timestamptz{Time: req.FireAt, Valid: true},
		Recurrence: "", // one-shot
		TimeoutMs:  handler.TimeoutMs,
	})
	if err != nil {
		h.logger.Error("insert scheduled fire", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to schedule")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": uuid.UUID(id.Bytes).String()})
}

// CancelScheduledFire handles DELETE /api/agent/schedules/{id}. Agent-scoped
// (no-op if the fire already fired or belongs to another agent).
func (h *Handler) CancelScheduledFire(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	q := dbq.New(h.db.Pool())
	if err := q.CancelScheduledFire(r.Context(), dbq.CancelScheduledFireParams{
		ID:      toPgUUID(id),
		AgentID: toPgUUID(agentID),
	}); err != nil {
		h.logger.Error("cancel scheduled fire", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to cancel")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListScheduledFires handles GET /api/agent/schedules[?slug=] — the agent's
// pending fires (optionally one slug).
func (h *Handler) ListScheduledFires(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	q := dbq.New(h.db.Pool())
	rows, err := q.ListScheduledFires(r.Context(), dbq.ListScheduledFiresParams{
		AgentID: toPgUUID(agentID),
		Slug:    r.URL.Query().Get("slug"),
	})
	if err != nil {
		h.logger.Error("list scheduled fires", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to list")
		return
	}
	fires := make([]wire.ScheduledFire, len(rows))
	for i, f := range rows {
		fires[i] = wire.ScheduledFire{
			ID:         uuid.UUID(f.ID.Bytes).String(),
			Slug:       f.Slug,
			Kind:       f.Source,
			FireAt:     f.FireAt.Time,
			Status:     f.Status,
			Recurrence: f.Recurrence,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"fires": fires})
}
