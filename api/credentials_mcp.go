package api

import (
	"net/http"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/go-chi/chi/v5"
)

// mcpServerInfo is the wire shape ListMCPServers returns.
type mcpServerInfo struct {
	ID             string     `json:"id"`
	Slug           string     `json:"slug"`
	Name           string     `json:"name"`
	URL            string     `json:"url"`
	AuthMode       string     `json:"authMode"`
	Authorized     bool       `json:"authorized"`
	HasOAuthApp    bool       `json:"hasOauthApp"`
	ToolCount      int        `json:"toolCount"`
	AuthURL        string     `json:"authUrl,omitempty"`
	TokenExpiresAt *time.Time `json:"tokenExpiresAt,omitempty"`
	LastSyncedAt   *time.Time `json:"lastSyncedAt,omitempty"`
}

// ListMCPServers handles GET /api/v1/agents/{agentID}/mcp-servers.
func (h *credentialHandler) ListMCPServers(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agentID")
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.ListMCPServers(r.Context(), p, agentID)
	if err != nil {
		writeConnError(w, err, "failed to list MCP servers")
		return
	}
	out := make([]mcpServerInfo, len(rows))
	for i, m := range rows {
		out[i] = mcpServerInfo{
			ID:             m.ID.String(),
			Slug:           m.Slug,
			Name:           m.Name,
			URL:            m.URL,
			AuthMode:       m.AuthMode,
			Authorized:     m.Authorized,
			HasOAuthApp:    m.HasOAuthApp,
			ToolCount:      m.ToolCount,
			AuthURL:        buildMCPAuthURL(h.svc.PublicURL(), agentID, m.Slug, m.AuthMode),
			TokenExpiresAt: m.TokenExpiresAt,
			LastSyncedAt:   m.LastSyncedAt,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mcpServers":       out,
		"oauthCallbackUrl": h.svc.PublicURL() + "/api/v1/credentials/oauth/callback",
	})
}

// MCPCredentialStatus handles GET /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials.
func (h *credentialHandler) MCPCredentialStatus(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFromRequest(r)
	st, err := h.svc.MCPCredentialStatus(r.Context(), p, agentID, slug)
	if err != nil {
		writeConnError(w, err, "failed to get MCP server")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"slug": st.Slug, "name": st.Name, "authMode": st.AuthMode, "authorized": st.Authorized,
	})
}

// SetMCPToken handles POST /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials.
func (h *credentialHandler) SetMCPToken(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req airlockv1.SetAPIKeyRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	st, err := h.svc.SetMCPToken(r.Context(), p, agentID, slug, req.ApiKey)
	if err != nil {
		writeConnError(w, err, "failed to store token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"slug": st.Slug, "name": st.Name, "authMode": st.AuthMode, "authorized": st.Authorized,
	})
}

// RevokeMCPCredential handles DELETE /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials.
func (h *credentialHandler) RevokeMCPCredential(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.RevokeMCPCredential(r.Context(), p, agentID, slug); err != nil {
		writeConnError(w, err, "failed to revoke credential")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TestMCPCredential handles POST /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials/test.
func (h *credentialHandler) TestMCPCredential(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req airlockv1.SetAPIKeyRequest
	_ = decodeProto(r, &req)
	p := principalFromRequest(r)
	res, err := h.svc.TestMCPCredential(r.Context(), p, agentID, slug, req.ApiKey)
	if err != nil {
		writeConnError(w, err, "failed to test credential")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.TestCredentialResponse{
		Success: res.Success, Message: res.Message,
	})
}

// RevokeMCPOAuthApp handles DELETE /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials/oauth-app.
func (h *credentialHandler) RevokeMCPOAuthApp(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.RevokeMCPOAuthApp(r.Context(), p, agentID, slug); err != nil {
		writeConnError(w, err, "failed to revoke OAuth app")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetMCPOAuthApp handles PUT /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials/oauth-app.
func (h *credentialHandler) SetMCPOAuthApp(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req airlockv1.SetOAuthAppRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	st, err := h.svc.SetMCPOAuthApp(r.Context(), p, agentID, slug, req.ClientId, req.ClientSecret)
	if err != nil {
		writeConnError(w, err, "failed to update OAuth app")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"slug": st.Slug, "name": st.Name, "authMode": st.AuthMode, "authorized": st.Authorized,
	})
}

// MCPOAuthStart handles POST /api/v1/credentials/mcp/oauth/start.
func (h *credentialHandler) MCPOAuthStart(w http.ResponseWriter, r *http.Request) {
	var req airlockv1.OAuthStartRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agentID, err := parseUUID(req.AgentId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent_id")
		return
	}
	p := principalFromRequest(r)
	authURL, err := h.svc.MCPOAuthStart(r.Context(), p, agentID, req.Slug, req.RedirectUri)
	if err != nil {
		writeConnError(w, err, "failed to start OAuth flow")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.OAuthStartResponse{AuthorizeUrl: authURL})
}
