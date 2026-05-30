package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/execproxy"
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

// execEndpointDTO is the wire shape the operator UI consumes.
type execEndpointDTO struct {
	ID                 string `json:"id"`
	Slug               string `json:"slug"`
	Description        string `json:"description"`
	LLMHint            string `json:"llmHint"`
	Access             string `json:"access"`
	Transport          string `json:"transport"`
	Host               string `json:"host"`
	Port               int32  `json:"port"`
	SSHUser            string `json:"sshUser"`
	PublicKeyOpenSSH   string `json:"publicKeyOpenssh"`
	PublicKeyComment   string `json:"publicKeyComment"`
	HostKeyFingerprint string `json:"hostKeyFingerprint"`
	HostKeyPinnedAt    string `json:"hostKeyPinnedAt"`
	LastUsedAt         string `json:"lastUsedAt"`
}

func rowToDTO(ep dbq.AgentExecEndpoint) execEndpointDTO {
	dto := execEndpointDTO{
		ID:               uuid.UUID(ep.ID.Bytes).String(),
		Slug:             ep.Slug,
		Description:      ep.Description,
		LLMHint:          ep.LlmHint,
		Access:           ep.Access,
		Transport:        ep.Transport.String,
		Host:             ep.Host.String,
		SSHUser:          ep.SshUser.String,
		PublicKeyOpenSSH: ep.PublicKeyOpenssh.String,
		PublicKeyComment: ep.PublicKeyComment.String,
	}
	if ep.Port.Valid {
		dto.Port = ep.Port.Int32
	}
	if ep.HostKeyOpenssh.Valid && ep.HostKeyOpenssh.String != "" {
		dto.HostKeyFingerprint = execproxy.HostKeyFingerprint(ep.HostKeyOpenssh.String)
	}
	if ep.HostKeyPinnedAt.Valid {
		dto.HostKeyPinnedAt = ep.HostKeyPinnedAt.Time.UTC().Format(time.RFC3339)
	}
	if ep.LastUsedAt.Valid {
		dto.LastUsedAt = ep.LastUsedAt.Time.UTC().Format(time.RFC3339)
	}
	return dto
}

func writeExecError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, execsvc.ErrKeypairAfterConfigure):
		writeJSONError(w, http.StatusInternalServerError, "configured but keypair generation failed")
	case errors.Is(err, service.ErrInvalidInput):
		writeJSONError(w, status, err.Error())
	case errors.Is(err, service.ErrNotFound):
		writeJSONError(w, status, err.Error())
	default:
		writeJSONError(w, status, fallback)
	}
}

// parseAgentSlug extracts and validates the agent ID + slug from chi.
func parseAgentSlug(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid agent id")
		return uuid.Nil, "", false
	}
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeJSONError(w, http.StatusBadRequest, "slug is required")
		return uuid.Nil, "", false
	}
	return agentID, slug, true
}

// List handles GET /api/v1/agents/{agentID}/exec-endpoints.
func (h *execEndpointsHandler) List(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.List(r.Context(), p, agentID)
	if err != nil {
		writeExecError(w, err, "failed to list exec endpoints")
		return
	}
	out := make([]execEndpointDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToDTO(row))
	}
	writeJSON(w, http.StatusOK, out)
}

// Configure handles PUT /api/v1/agents/{agentID}/exec-endpoints/{slug}.
func (h *execEndpointsHandler) Configure(w http.ResponseWriter, r *http.Request) {
	agentID, slug, ok := parseAgentSlug(w, r)
	if !ok {
		return
	}
	var req struct {
		Host    string `json:"host"`
		Port    int32  `json:"port"`
		SSHUser string `json:"sshUser"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	ep, err := h.svc.Configure(r.Context(), p, agentID, slug, execsvc.ConfigureRequest{
		Host: req.Host, Port: req.Port, SSHUser: req.SSHUser,
	})
	if err != nil {
		writeExecError(w, err, "failed to configure exec endpoint")
		return
	}
	writeJSON(w, http.StatusOK, rowToDTO(ep))
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
	writeJSON(w, http.StatusOK, rowToDTO(ep))
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
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         res.OK,
		"exitCode":   res.ExitCode,
		"durationMs": res.DurationMs,
		"stdout":     res.Stdout,
		"stderr":     res.Stderr,
		"error":      res.Error,
	})
}
