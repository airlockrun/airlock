package api

import (
	"encoding/json"
	"net/http"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// ListMCPServers handles GET /api/v1/agents/{agentID}/mcp-servers.
func (h *credentialHandler) ListMCPServers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agentID")
		return
	}

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	rows, err := q.ListMCPServersWithStatus(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list MCP servers failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list MCP servers")
		return
	}

	servers := make([]mcpServerInfo, len(rows))
	for i, s := range rows {
		info := mcpServerInfo{
			ID:          pgUUID(s.ID).String(),
			Slug:        s.Slug,
			Name:        s.Name,
			URL:         s.Url,
			AuthMode:    s.AuthMode,
			Authorized:  s.Authorized,
			HasOAuthApp: s.HasOauthApp,
			AuthURL:     buildMCPAuthURL(h.publicURL, agentID, s.Slug, s.AuthMode),
		}
		// Count tools from tool_schemas JSON array.
		var tools []json.RawMessage
		if err := json.Unmarshal(s.ToolSchemas, &tools); err == nil {
			info.ToolCount = len(tools)
		}
		if s.TokenExpiresAt.Valid {
			info.TokenExpiresAt = &s.TokenExpiresAt.Time
		}
		if s.LastSyncedAt.Valid {
			info.LastSyncedAt = &s.LastSyncedAt.Time
		}
		servers[i] = info
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"mcpServers":       servers,
		"oauthCallbackUrl": h.publicURL + "/api/v1/credentials/oauth/callback",
	})
}

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

// MCPCredentialStatus handles GET /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials.
func (h *credentialHandler) MCPCredentialStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, slug, err := h.resolveMCPSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	server, err := q.GetMCPServerBySlug(ctx, dbq.GetMCPServerBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "MCP server not found")
			return
		}
		h.logger.Error("get MCP server failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get MCP server")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"slug":       server.Slug,
		"name":       server.Name,
		"authMode":   server.AuthMode,
		"authorized": server.Credentials != "",
	})
}

// SetMCPToken handles POST /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials.
func (h *credentialHandler) SetMCPToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, slug, err := h.resolveMCPSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req airlockv1.SetAPIKeyRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	server, err := q.GetMCPServerBySlug(ctx, dbq.GetMCPServerBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "MCP server not found")
			return
		}
		h.logger.Error("get MCP server failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get MCP server")
		return
	}
	if server.AuthMode == "oauth" || server.AuthMode == "oauth_discovery" {
		writeError(w, http.StatusBadRequest, "use OAuth flow for OAuth MCP servers")
		return
	}

	encKey, err := h.encryptor.Encrypt(req.ApiKey)
	if err != nil {
		h.logger.Error("encrypt MCP token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	if err := q.UpdateMCPServerCredentials(ctx, dbq.UpdateMCPServerCredentialsParams{
		AgentID:     toPgUUID(agentID),
		Slug:        slug,
		Credentials: encKey,
	}); err != nil {
		h.logger.Error("store MCP token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to store token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"slug":       server.Slug,
		"name":       server.Name,
		"authMode":   server.AuthMode,
		"authorized": true,
	})
}

// RevokeMCPCredential handles DELETE /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials.
func (h *credentialHandler) RevokeMCPCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, slug, err := h.resolveMCPSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	if err := q.ClearMCPServerCredentials(ctx, dbq.ClearMCPServerCredentialsParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	}); err != nil {
		h.logger.Error("revoke MCP credential failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to revoke credential")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetMCPOAuthApp handles PUT /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials/oauth-app.
func (h *credentialHandler) SetMCPOAuthApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, slug, err := h.resolveMCPSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req airlockv1.SetOAuthAppRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	server, err := q.GetMCPServerForOAuth(ctx, dbq.GetMCPServerForOAuthParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "MCP server not found")
			return
		}
		h.logger.Error("get MCP server failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get MCP server")
		return
	}
	if server.AuthMode != "oauth" && server.AuthMode != "oauth_discovery" {
		writeError(w, http.StatusBadRequest, "MCP server is not OAuth — use token endpoint")
		return
	}

	encClientID, err := h.encryptor.Encrypt(req.ClientId)
	if err != nil {
		h.logger.Error("encrypt client_id failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}
	encClientSecret, err := h.encryptor.Encrypt(req.ClientSecret)
	if err != nil {
		h.logger.Error("encrypt client_secret failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	if err := q.UpdateMCPServerOAuthApp(ctx, dbq.UpdateMCPServerOAuthAppParams{
		AgentID:      toPgUUID(agentID),
		Slug:         slug,
		ClientID:     encClientID,
		ClientSecret: encClientSecret,
	}); err != nil {
		h.logger.Error("update MCP OAuth app failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to update OAuth app")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"slug":       server.Slug,
		"name":       server.Name,
		"authMode":   server.AuthMode,
		"authorized": false,
	})
}

// MCPOAuthStart handles POST /api/v1/credentials/mcp/oauth/start.
func (h *credentialHandler) MCPOAuthStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	server, err := q.GetMCPServerForOAuth(ctx, dbq.GetMCPServerForOAuthParams{
		AgentID: toPgUUID(agentID),
		Slug:    req.Slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "MCP server not found")
			return
		}
		h.logger.Error("get MCP server failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get MCP server")
		return
	}
	if server.AuthMode != "oauth" && server.AuthMode != "oauth_discovery" {
		writeError(w, http.StatusBadRequest, "MCP server is not OAuth")
		return
	}
	if server.ClientID == "" {
		writeError(w, http.StatusBadRequest, "OAuth app not configured. Set client_id and client_secret first.")
		return
	}

	clientID, err := h.encryptor.Decrypt(server.ClientID)
	if err != nil {
		h.logger.Error("decrypt client_id failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	verifier, challenge, err := oauth.GeneratePKCE()
	if err != nil {
		h.logger.Error("generate PKCE failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to generate PKCE")
		return
	}

	state, err := oauth.GenerateState()
	if err != nil {
		h.logger.Error("generate state failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to generate state")
		return
	}

	encVerifier, err := h.encryptor.Encrypt(verifier)
	if err != nil {
		h.logger.Error("encrypt verifier failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	if err := q.CreateOAuthState(ctx, dbq.CreateOAuthStateParams{
		State:        state,
		AgentID:      toPgUUID(agentID),
		Slug:         req.Slug,
		CodeVerifier: encVerifier,
		RedirectUri:  req.RedirectUri,
		ExpiresAt:    pgtype.Timestamptz{Time: time.Now().Add(10 * time.Minute), Valid: true},
		SourceType:   "mcp",
	}); err != nil {
		h.logger.Error("create oauth state failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to save state")
		return
	}

	callbackURL := h.publicURL + "/api/v1/credentials/oauth/callback"
	authURL, err := h.oauthClient.BuildAuthURL(server.AuthUrl, clientID, callbackURL, state, challenge, server.Scopes)
	if err != nil {
		h.logger.Error("build auth URL failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to build authorization URL")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.OAuthStartResponse{
		AuthorizeUrl: authURL,
	})
}

// resolveMCPSlug extracts agentID and MCP server slug from the request URL.
func (h *credentialHandler) resolveMCPSlug(r *http.Request) (agentID [16]byte, slug string, err error) {
	id, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		return id, "", err
	}
	slug = chi.URLParam(r, "slug")
	if slug == "" {
		return id, "", err
	}
	return id, slug, nil
}
