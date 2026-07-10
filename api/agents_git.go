package api

import (
	"net/http"
	"strings"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	agentssvc "github.com/airlockrun/airlock/service/agents"
	"github.com/go-chi/chi/v5"
)

// ConnectGit handles POST /api/v1/agents/{agentID}/git/connect.
func (h *agentsHandler) ConnectGit(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	req := &airlockv1.ConnectAgentGitRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	cfg, err := h.svc.ConnectGit(r.Context(), p, agentID, agentssvc.ConnectGitRequest{
		RemoteURL:     req.GitRemoteUrl,
		CredentialID:  req.GitCredentialId,
		DefaultBranch: req.DefaultBranch,
		Mode:          req.GitMode,
	})
	if err != nil {
		writeAgentsError(w, err, "failed to connect git remote")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.ConnectAgentGitResponse{
		Config: h.buildGitConfigProto(agentID.String(), cfg),
	})
}

// DisconnectGit handles POST /api/v1/agents/{agentID}/git/disconnect.
func (h *agentsHandler) DisconnectGit(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.DisconnectGit(r.Context(), p, agentID); err != nil {
		writeAgentsError(w, err, "failed to disconnect git remote")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetGitConfig handles GET /api/v1/agents/{agentID}/git.
func (h *agentsHandler) GetGitConfig(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	cfg, err := h.svc.GetGitConfig(r.Context(), p, agentID)
	if err != nil {
		writeAgentsError(w, err, "failed to load git config")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.GetAgentGitConfigResponse{
		Config: h.buildGitConfigProto(agentID.String(), cfg),
	})
}

// buildGitConfigProto assembles the proto representation. WebhookUrl +
// WebhookSecret are populated only when a remote is connected (non-empty
// RemoteURL).
func (h *agentsHandler) buildGitConfigProto(agentID string, cfg agentssvc.GitConfig) *airlockv1.AgentGitConfig {
	out := &airlockv1.AgentGitConfig{
		AgentId:           agentID,
		GitRemoteUrl:      cfg.RemoteURL,
		GitCredentialId:   cfg.CredentialID,
		GitCredentialName: cfg.CredentialName,
		DefaultBranch:     cfg.DefaultBranch,
		LastSyncedRef:     cfg.LastSyncedRef,
		GitMode:           cfg.Mode,
	}
	if cfg.RemoteURL != "" {
		out.WebhookUrl = strings.TrimRight(h.publicURL, "/") + "/webhooks/git/" + agentID
		out.WebhookSecret = cfg.WebhookSecret
	}
	return out
}
