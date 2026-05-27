package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/siblings"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// siblingsHandler is the thin HTTP wrapper around siblings.Service:
// parse URL/body, delegate, render. Authorization and DB work live in
// the service.
type siblingsHandler struct {
	svc *siblings.Service
}

func newSiblingsHandler(svc *siblings.Service) *siblingsHandler {
	if svc == nil {
		panic("api: siblings.Service is required")
	}
	return &siblingsHandler{svc: svc}
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

// parentAgentID extracts and parses {agentID} from the URL. On a bad
// UUID it writes a 400 and returns ok=false; callers should return.
func parentAgentID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid agent ID")
		return uuid.Nil, false
	}
	return id, true
}

// writeSiblingsError renders a service error using per-sentinel strings
// for siblings endpoints. fallback is the generic 500 message.
func writeSiblingsError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	var msg string
	switch {
	case errors.Is(err, service.ErrUnauthorized):
		msg = "unauthorized"
	case errors.Is(err, service.ErrForbidden):
		msg = "agent admin access required"
	case errors.Is(err, service.ErrNotFound):
		msg = "agent not found"
	case errors.Is(err, service.ErrInvalidInput):
		msg = "invalid input"
	case errors.Is(err, service.ErrConflict):
		msg = "already in list"
	default:
		msg = fallback
	}
	writeJSONError(w, status, msg)
}

// List GET /api/v1/agents/{agentID}/siblings.
func (h *siblingsHandler) List(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	rows, err := h.svc.List(r.Context(), userID, parentID)
	if err != nil {
		writeSiblingsError(w, err, "list siblings")
		return
	}
	out := make([]siblingDTO, 0, len(rows))
	for _, s := range rows {
		out = append(out, siblingDTO{
			ID:                s.ID.String(),
			Slug:              s.Slug,
			Name:              s.Name,
			Description:       s.Description,
			AllowNonMemberMcp: s.AllowNonMemberMcp,
			AllowPublicMcp:    s.AllowPublicMcp,
			CreatedAt:         s.CreatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// ListAddable GET /api/v1/agents/{agentID}/siblings/addable.
func (h *siblingsHandler) ListAddable(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	rows, err := h.svc.ListAddable(r.Context(), userID, parentID)
	if err != nil {
		writeSiblingsError(w, err, "list addable siblings")
		return
	}
	out := make([]addableSiblingDTO, 0, len(rows))
	for _, s := range rows {
		out = append(out, addableSiblingDTO{
			ID:                s.ID.String(),
			Slug:              s.Slug,
			Name:              s.Name,
			Description:       s.Description,
			AllowNonMemberMcp: s.AllowNonMemberMcp,
			IsMember:          s.IsMember,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// Add POST /api/v1/agents/{agentID}/siblings — body: {"siblingId": "..."}.
func (h *siblingsHandler) Add(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
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
	userID := auth.UserIDFromContext(r.Context())
	if err := h.svc.Add(r.Context(), userID, parentID, siblingID); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidInput):
			writeJSONError(w, http.StatusBadRequest, "agent cannot be its own sibling")
		case errors.Is(err, service.ErrUnauthorized):
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		case errors.Is(err, service.ErrForbidden):
			writeJSONError(w, http.StatusForbidden, "you are not allowed to add this agent as a sibling")
		case errors.Is(err, service.ErrConflict):
			writeJSONError(w, http.StatusConflict, "already in list")
		default:
			writeJSONError(w, http.StatusInternalServerError, "add sibling")
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// Remove DELETE /api/v1/agents/{agentID}/siblings/{siblingID}.
func (h *siblingsHandler) Remove(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	siblingID, err := uuid.Parse(chi.URLParam(r, "siblingID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid sibling ID")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	if err := h.svc.Remove(r.Context(), userID, parentID, siblingID); err != nil {
		writeSiblingsError(w, err, "remove sibling")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetA2ASettings GET /api/v1/agents/{agentID}/a2a-settings.
func (h *siblingsHandler) GetA2ASettings(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	s, err := h.svc.GetSettings(r.Context(), userID, parentID)
	if err != nil {
		writeSiblingsError(w, err, "get settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"allowNonMemberMcp": s.AllowNonMemberMcp,
		"allowPublicMcp":    s.AllowPublicMcp,
	})
}

// UpdateA2ASettings PUT /api/v1/agents/{agentID}/a2a-settings —
// body: {"allowNonMemberMcp": bool, "allowPublicMcp": bool}.
func (h *siblingsHandler) UpdateA2ASettings(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
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
	userID := auth.UserIDFromContext(r.Context())
	out, err := h.svc.UpdateSettings(r.Context(), userID, parentID, siblings.A2ASettings{
		AllowNonMemberMcp: body.AllowNonMemberMcp,
		AllowPublicMcp:    body.AllowPublicMcp,
	})
	if err != nil {
		writeSiblingsError(w, err, "update settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"allowNonMemberMcp": out.AllowNonMemberMcp,
		"allowPublicMcp":    out.AllowPublicMcp,
	})
}
