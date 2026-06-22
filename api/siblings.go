package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
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

// parentAgentID extracts and parses {agentID} from the URL. On a bad
// UUID it writes a 400 and returns ok=false; callers should return.
func parentAgentID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
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
	writeError(w, status, msg)
}

// List GET /api/v1/agents/{agentID}/siblings.
func (h *siblingsHandler) List(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.List(r.Context(), p, parentID)
	if err != nil {
		writeSiblingsError(w, err, "list siblings")
		return
	}
	out := make([]*airlockv1.SiblingInfo, 0, len(rows))
	for _, s := range rows {
		out = append(out, convert.SiblingToProto(s))
	}
	writeProto(w, http.StatusOK, &airlockv1.ListSiblingsResponse{Siblings: out})
}

// ListAddable GET /api/v1/agents/{agentID}/siblings/addable.
func (h *siblingsHandler) ListAddable(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.ListAddable(r.Context(), p, parentID)
	if err != nil {
		writeSiblingsError(w, err, "list addable siblings")
		return
	}
	out := make([]*airlockv1.AddableSiblingInfo, 0, len(rows))
	for _, s := range rows {
		out = append(out, convert.AddableSiblingToProto(s))
	}
	writeProto(w, http.StatusOK, &airlockv1.ListAddableSiblingsResponse{Agents: out})
}

// ListInbound GET /api/v1/agents/{agentID}/siblings/inbound — the agents
// that have added this one to their address book (reverse direction).
func (h *siblingsHandler) ListInbound(w http.ResponseWriter, r *http.Request) {
	agentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.ListInbound(r.Context(), p, agentID)
	if err != nil {
		writeSiblingsError(w, err, "list inbound siblings")
		return
	}
	out := make([]*airlockv1.InboundSiblingInfo, 0, len(rows))
	for _, s := range rows {
		out = append(out, convert.InboundSiblingToProto(s))
	}
	writeProto(w, http.StatusOK, &airlockv1.ListInboundSiblingsResponse{Siblings: out})
}

// Add POST /api/v1/agents/{agentID}/siblings — body:
// {"siblingId": "...", "maxAccess": "public|user|admin"}.
func (h *siblingsHandler) Add(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	var body struct {
		SiblingID string `json:"siblingId"`
		MaxAccess string `json:"maxAccess"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	siblingID, err := uuid.Parse(body.SiblingID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid siblingId")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Add(r.Context(), p, parentID, siblingID, agentsdk.Access(body.MaxAccess)); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "agent cannot be its own sibling")
		case errors.Is(err, service.ErrUnauthorized):
			writeError(w, http.StatusUnauthorized, "unauthorized")
		case errors.Is(err, service.ErrForbidden):
			writeError(w, http.StatusForbidden, "you are not allowed to add this agent as a sibling")
		case errors.Is(err, service.ErrConflict):
			writeError(w, http.StatusConflict, "already in list")
		default:
			writeError(w, http.StatusInternalServerError, "add sibling")
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// UpdateMaxAccess PATCH /api/v1/agents/{agentID}/siblings/{siblingID} —
// body: {"maxAccess": "public|user|admin"}. Edits the per-edge ceiling.
func (h *siblingsHandler) UpdateMaxAccess(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	siblingID, err := uuid.Parse(chi.URLParam(r, "siblingID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid sibling ID")
		return
	}
	var body struct {
		MaxAccess string `json:"maxAccess"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.UpdateMaxAccess(r.Context(), p, parentID, siblingID, agentsdk.Access(body.MaxAccess)); err != nil {
		writeSiblingsError(w, err, "update sibling")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Remove DELETE /api/v1/agents/{agentID}/siblings/{siblingID}.
func (h *siblingsHandler) Remove(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	siblingID, err := uuid.Parse(chi.URLParam(r, "siblingID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid sibling ID")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Remove(r.Context(), p, parentID, siblingID); err != nil {
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
	p := principalFromRequest(r)
	s, err := h.svc.GetSettings(r.Context(), p, parentID)
	if err != nil {
		writeSiblingsError(w, err, "get settings")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.GetAgentSharingResponse{
		Settings: convert.A2ASettingsToProto(s),
	})
}

// UpdateA2ASettings PUT /api/v1/agents/{agentID}/a2a-settings —
// body: UpdateAgentSharingRequest proto.
func (h *siblingsHandler) UpdateA2ASettings(w http.ResponseWriter, r *http.Request) {
	parentID, ok := parentAgentID(w, r)
	if !ok {
		return
	}
	var req airlockv1.UpdateAgentSharingRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	in := siblings.A2ASettings{}
	if req.Settings != nil {
		in.McpEnabled = req.Settings.McpEnabled
		in.AllowPublicMcp = req.Settings.AllowPublicMcp
		in.AllowPublicRoutes = req.Settings.AllowPublicRoutes
	}
	p := principalFromRequest(r)
	out, err := h.svc.UpdateSettings(r.Context(), p, parentID, in)
	if err != nil {
		writeSiblingsError(w, err, "update settings")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.UpdateAgentSharingResponse{
		Settings: convert.A2ASettingsToProto(out),
	})
}
