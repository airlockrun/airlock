package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// siblingsHandler exposes the per-agent sibling address book — the
// list of OTHER agents the editing user (admin of this agent) wants
// the LLM to be able to call via the new A2A MCP endpoint. Membership
// in this list is a discovery aid only; authorization at call time is
// always evaluated fresh against the target's allow_*_mcp settings.
type siblingsHandler struct {
	db     *db.DB
	logger *zap.Logger
}

func newSiblingsHandler(d *db.DB, logger *zap.Logger) *siblingsHandler {
	return &siblingsHandler{db: d, logger: logger}
}

type siblingDTO struct {
	ID                string `json:"id"`
	Slug              string `json:"slug"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	AllowNonMemberMcp bool   `json:"allowNonMemberMcp"`
	AllowPublicMcp    bool   `json:"allowPublicMcp,omitempty"`
	CreatedAt         string `json:"createdAt,omitempty"`
}

type addableSiblingDTO struct {
	ID                string `json:"id"`
	Slug              string `json:"slug"`
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	AllowNonMemberMcp bool   `json:"allowNonMemberMcp"`
	IsMember          bool   `json:"isMember"`
}

// List GET /api/v1/agents/{agentID}/siblings — current address book.
// Requires agent-admin on the parent (we read the parent's siblings;
// only an admin can edit them, so List is also admin-gated for
// consistency).
func (h *siblingsHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentID, ok := h.requireParentAdmin(ctx, w, r)
	if !ok {
		return
	}
	q := dbq.New(h.db.Pool())
	rows, err := q.ListSiblings(ctx, pgtype.UUID{Bytes: parentID, Valid: true})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list siblings")
		return
	}
	out := make([]siblingDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, siblingDTO{
			ID:                uuid.UUID(r.ID.Bytes).String(),
			Slug:              r.Slug,
			Name:              r.Name,
			Description:       r.Description,
			AllowNonMemberMcp: r.AllowNonMemberMcp,
			AllowPublicMcp:    r.AllowPublicMcp,
			CreatedAt:         r.CreatedAt.Time.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// ListAddable GET /api/v1/agents/{agentID}/siblings/addable — drives
// the "pick another agent to add" picker on the settings page.
// Returns the agents the EDITING user (not the parent agent's owner)
// is allowed to add as a sibling, modulo what's already in the list
// or the parent itself.
func (h *siblingsHandler) ListAddable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentID, ok := h.requireParentAdmin(ctx, w, r)
	if !ok {
		return
	}
	userID := auth.UserIDFromContext(ctx)
	q := dbq.New(h.db.Pool())
	rows, err := q.ListAddableSiblings(ctx, dbq.ListAddableSiblingsParams{
		ParentAgentID: pgtype.UUID{Bytes: parentID, Valid: true},
		UserID:        pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list addable siblings")
		return
	}
	out := make([]addableSiblingDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, addableSiblingDTO{
			ID:                uuid.UUID(r.ID.Bytes).String(),
			Slug:              r.Slug,
			Name:              r.Name,
			Description:       r.Description,
			AllowNonMemberMcp: r.AllowNonMemberMcp,
			IsMember:          r.IsMember,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// Add POST /api/v1/agents/{agentID}/siblings — body: {"siblingId": "..."}.
// Atomic per the AddSiblingIfAllowed query: the row only lands if the
// editing user is a member of the sibling OR sibling has
// allow_non_member_mcp=true. RowsAffected = 0 maps to 403.
func (h *siblingsHandler) Add(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentID, ok := h.requireParentAdmin(ctx, w, r)
	if !ok {
		return
	}
	var body struct {
		SiblingID string `json:"siblingId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	siblingID, err := uuid.Parse(body.SiblingID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid siblingId")
		return
	}
	if siblingID == parentID {
		writeJSONError(w, http.StatusBadRequest, "agent cannot be its own sibling")
		return
	}
	userID := auth.UserIDFromContext(ctx)
	q := dbq.New(h.db.Pool())
	rows, err := q.AddSiblingIfAllowed(ctx, dbq.AddSiblingIfAllowedParams{
		ParentAgentID:  pgtype.UUID{Bytes: parentID, Valid: true},
		SiblingAgentID: pgtype.UUID{Bytes: siblingID, Valid: true},
		UserID:         pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		// Unique-violation = already in list. Surface as 409.
		writeJSONError(w, http.StatusConflict, "already in list")
		return
	}
	if rows == 0 {
		writeJSONError(w, http.StatusForbidden, "you are not allowed to add this agent as a sibling")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// Remove DELETE /api/v1/agents/{agentID}/siblings/{siblingID}.
func (h *siblingsHandler) Remove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentID, ok := h.requireParentAdmin(ctx, w, r)
	if !ok {
		return
	}
	siblingID, err := uuid.Parse(chi.URLParam(r, "siblingID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid sibling ID")
		return
	}
	q := dbq.New(h.db.Pool())
	if err := q.RemoveSibling(ctx, dbq.RemoveSiblingParams{
		ParentAgentID:  pgtype.UUID{Bytes: parentID, Valid: true},
		SiblingAgentID: pgtype.UUID{Bytes: siblingID, Valid: true},
	}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "remove sibling")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requireParentAdmin checks the caller is an admin of the parent
// agent; returns the parent agent's UUID and ok=true when so.
func (h *siblingsHandler) requireParentAdmin(ctx context.Context, w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	parentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid agent ID")
		return uuid.Nil, false
	}
	userID := auth.UserIDFromContext(ctx)
	if userID == uuid.Nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return uuid.Nil, false
	}
	q := dbq.New(h.db.Pool())
	access := trigger.ResolveAgentAccess(ctx, q, parentID, userID)
	if access != "admin" {
		writeJSONError(w, http.StatusForbidden, "agent admin access required")
		return uuid.Nil, false
	}
	return parentID, true
}

// GetA2ASettings GET /api/v1/agents/{agentID}/a2a-settings.
func (h *siblingsHandler) GetA2ASettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentID, ok := h.requireParentAdmin(ctx, w, r)
	if !ok {
		return
	}
	q := dbq.New(h.db.Pool())
	a, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: parentID, Valid: true})
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"allowNonMemberMcp": a.AllowNonMemberMcp,
		"allowPublicMcp":    a.AllowPublicMcp,
	})
}

// UpdateA2ASettings PUT /api/v1/agents/{agentID}/a2a-settings —
// body: {"allowNonMemberMcp": bool, "allowPublicMcp": bool}. The
// CHECK constraint rejects (public ∧ ¬non-member); we silently flip
// non-member on whenever public is true so the UI's "make public"
// toggle is a one-click affordance.
func (h *siblingsHandler) UpdateA2ASettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	parentID, ok := h.requireParentAdmin(ctx, w, r)
	if !ok {
		return
	}
	var body struct {
		AllowNonMemberMcp bool `json:"allowNonMemberMcp"`
		AllowPublicMcp    bool `json:"allowPublicMcp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.AllowPublicMcp {
		body.AllowNonMemberMcp = true
	}
	q := dbq.New(h.db.Pool())
	if err := q.UpdateAgentA2ASettings(ctx, dbq.UpdateAgentA2ASettingsParams{
		ID:                pgtype.UUID{Bytes: parentID, Valid: true},
		AllowNonMemberMcp: body.AllowNonMemberMcp,
		AllowPublicMcp:    body.AllowPublicMcp,
	}); err != nil {
		h.logger.Error("update a2a settings", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "update settings")
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// Compile-time guard against import-removal regressions.
var _ = errors.New
