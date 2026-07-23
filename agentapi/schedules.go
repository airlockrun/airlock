package agentapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// CreateScheduledFire idempotently arms a caller-identified one-shot fire.
func (h *Handler) CreateScheduledFire(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())

	var req wire.ScheduleRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id, err := uuid.Parse(req.ID)
	if err != nil || id == uuid.Nil || id.String() != req.ID || req.Slug == "" || req.FireAt.IsZero() {
		writeJSONError(w, http.StatusBadRequest, "canonical id, slug, and fireAt are required")
		return
	}
	fireAt := req.FireAt.UTC().Truncate(time.Microsecond)

	q := dbq.New(h.db.Pool())
	handler, err := q.GetScheduleHandler(r.Context(), dbq.GetScheduleHandlerParams{
		AgentID: toPgUUID(agentID),
		Slug:    req.Slug,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSONError(w, http.StatusBadRequest, "no registered schedule handler: "+req.Slug)
		return
	}
	if err != nil {
		h.logger.Error("get schedule handler", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to schedule")
		return
	}
	if handler.Kind != "schedule" || !handler.Enabled {
		writeJSONError(w, http.StatusBadRequest, "no registered schedule handler: "+req.Slug)
		return
	}

	inserted, err := q.InsertScheduledFire(r.Context(), dbq.InsertScheduledFireParams{
		ID:          toPgUUID(id),
		AgentID:     toPgUUID(agentID),
		Source:      "schedule",
		Slug:        req.Slug,
		FireAt:      pgtype.Timestamptz{Time: fireAt, Valid: true},
		Recurrence:  "", // one-shot
		TimeoutMs:   handler.TimeoutMs,
		MaxAttempts: 5,
	})
	if err != nil {
		h.logger.Error("insert scheduled fire", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to schedule")
		return
	}
	if inserted == 0 {
		existing, err := q.GetScheduledFire(r.Context(), dbq.GetScheduledFireParams{ID: toPgUUID(id), AgentID: toPgUUID(agentID)})
		if err != nil || existing.Source != "schedule" || existing.Slug != req.Slug || !existing.FireAt.Time.Equal(fireAt) {
			writeJSONError(w, http.StatusConflict, "schedule id conflicts with another occurrence")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
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
	if _, err := q.CancelScheduledFire(r.Context(), dbq.CancelScheduledFireParams{
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
