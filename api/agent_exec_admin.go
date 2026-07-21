package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	execsvc "github.com/airlockrun/airlock/service/execendpoints"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// execEndpointsHandler is the thin HTTP wrapper around execendpoints.Service.
type execEndpointsHandler struct {
	svc *execsvc.Service
}

func newExecEndpointsHandler(svc *execsvc.Service) *execEndpointsHandler {
	if svc == nil {
		panic("api: execendpoints.Service is required")
	}
	return &execEndpointsHandler{svc: svc}
}

func writeExecError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, execsvc.ErrKeypairAfterConfigure):
		writeError(w, http.StatusInternalServerError, "configured but keypair generation failed")
	case errors.Is(err, service.ErrInvalidInput):
		writeError(w, status, err.Error())
	case errors.Is(err, service.ErrNotFound):
		writeError(w, status, err.Error())
	default:
		writeError(w, status, fallback)
	}
}

// parseAgentSlug extracts and validates the agent ID + slug from chi.
func parseAgentSlug(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent id")
		return uuid.Nil, "", false
	}
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "slug is required")
		return uuid.Nil, "", false
	}
	return agentID, slug, true
}

// List handles GET /api/v1/agents/{agentID}/exec-endpoints.
func (h *execEndpointsHandler) List(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.List(r.Context(), p, agentID)
	if err != nil {
		writeExecError(w, err, "failed to list exec endpoints")
		return
	}
	out := make([]*airlockv1.ExecEndpointInfo, 0, len(rows))
	for _, row := range rows {
		out = append(out, convert.ExecNeedRowToProto(row))
	}
	writeProto(w, http.StatusOK, &airlockv1.ListExecEndpointsResponse{Endpoints: out})
}

// Configure handles PUT /api/v1/agents/{agentID}/exec-endpoints/{slug}.
func (h *execEndpointsHandler) Configure(w http.ResponseWriter, r *http.Request) {
	agentID, slug, ok := parseAgentSlug(w, r)
	if !ok {
		return
	}
	var req airlockv1.ConfigureExecEndpointRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	ep, err := h.svc.Configure(r.Context(), p, agentID, slug, execsvc.ConfigureRequest{
		Host: req.Host, Port: req.Port, SSHUser: req.SshUser, DisplayName: req.DisplayName, CreateNew: req.CreateNew,
	})
	if err != nil {
		writeExecError(w, err, "failed to configure exec endpoint")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.ConfigureExecEndpointResponse{
		Endpoint: convert.ExecEndpointRowToProto(ep),
	})
}

// RotateKeypair handles POST /api/v1/agents/{agentID}/exec-endpoints/{slug}/rotate-keypair.
func (h *execEndpointsHandler) RotateKeypair(w http.ResponseWriter, r *http.Request) {
	agentID, slug, ok := parseAgentSlug(w, r)
	if !ok {
		return
	}
	p := principalFromRequest(r)
	ep, err := h.svc.RotateKeypair(r.Context(), p, agentID, slug)
	if err != nil {
		writeExecError(w, err, "failed to rotate keypair")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.RotateExecKeypairResponse{
		Endpoint: convert.ExecEndpointRowToProto(ep),
	})
}

// UnpinHostKey handles POST /api/v1/agents/{agentID}/exec-endpoints/{slug}/unpin-host-key.
func (h *execEndpointsHandler) UnpinHostKey(w http.ResponseWriter, r *http.Request) {
	agentID, slug, ok := parseAgentSlug(w, r)
	if !ok {
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.UnpinHostKey(r.Context(), p, agentID, slug); err != nil {
		writeExecError(w, err, "failed to clear host key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Test handles POST /api/v1/agents/{agentID}/exec-endpoints/{slug}/test.
func (h *execEndpointsHandler) Test(w http.ResponseWriter, r *http.Request) {
	agentID, slug, ok := parseAgentSlug(w, r)
	if !ok {
		return
	}
	p := principalFromRequest(r)
	res, err := h.svc.Test(r.Context(), p, agentID, slug)
	if err != nil {
		writeExecError(w, err, "failed to load exec endpoint")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.TestExecEndpointResponse{
		Result: convert.ExecEndpointTestToProto(res),
	})
}
