package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/go-chi/chi/v5"
)

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
	out := make([]*airlockv1.MCPServerInfo, len(rows))
	for i, m := range rows {
		out[i] = convert.MCPServerToProto(m, h.svc.PublicURL(), agentID.String())
	}
	writeProto(w, http.StatusOK, &airlockv1.ListMCPServersResponse{
		McpServers:       out,
		OauthCallbackUrl: h.svc.PublicURL() + "/api/v1/credentials/oauth/callback",
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
	writeProto(w, http.StatusOK, &airlockv1.MCPCredentialStatusResponse{
		Status: convert.MCPStatusToProto(st),
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
	st, err := h.svc.SetMCPToken(r.Context(), p, agentID, slug, req.DisplayName, req.ApiKey, req.CreateNew)
	if err != nil {
		writeConnError(w, err, "failed to store token")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.MCPCredentialStatusResponse{
		Status: convert.MCPStatusToProto(st),
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
	writeProto(w, http.StatusOK, convert.TestCredentialResultToProto(res))
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
	st, err := h.svc.SetMCPOAuthApp(r.Context(), p, agentID, slug, req.DisplayName, req.ClientId, req.ClientSecret, req.CreateNew)
	if err != nil {
		writeConnError(w, err, "failed to update OAuth app")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.MCPCredentialStatusResponse{
		Status: convert.MCPStatusToProto(st),
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
