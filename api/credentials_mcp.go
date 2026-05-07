package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
		"authorized": server.AccessTokenRef != "",
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

	encKey, err := h.encryptor.Put(ctx, "mcp/"+pgUUID(server.ID).String()+"/access_token", req.ApiKey)
	if err != nil {
		h.logger.Error("encrypt MCP token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	if err := q.UpdateMCPServerCredentials(ctx, dbq.UpdateMCPServerCredentialsParams{
		AgentID:     toPgUUID(agentID),
		Slug:        slug,
		AccessTokenRef: encKey,
	}); err != nil {
		h.logger.Error("store MCP token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to store token")
		return
	}

	// Discover tools + push agent refresh, same as the OAuth callback. Best
	// effort — the response below still reports success even if discovery
	// fails, since the agent will retry on next sync.
	h.refreshMCPAfterAuth(ctx, uuid.UUID(agentID), slug, req.ApiKey)

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

// TestMCPCredential handles POST /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials/test.
// Probes the MCP server with a real tools/list call so we exercise the
// auth_injection path the runtime will actually use. Body is an optional
// SetAPIKeyRequest — if api_key is provided, that token is tested; otherwise
// the stored credential is used. Lets the dialog test before save.
func (h *credentialHandler) TestMCPCredential(w http.ResponseWriter, r *http.Request) {
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

	// Optional body lets the UI test a freshly-typed token without saving
	// first. Empty body falls back to the stored credential.
	var req airlockv1.SetAPIKeyRequest
	_ = decodeProto(r, &req)

	creds := req.ApiKey
	if creds == "" {
		if server.AccessTokenRef == "" {
			writeError(w, http.StatusBadRequest, "no credentials configured")
			return
		}
		creds, err = h.encryptor.Get(ctx, "mcp/"+pgUUID(server.ID).String()+"/access_token", server.AccessTokenRef)
		if err != nil {
			h.logger.Error("decrypt MCP token failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "decryption failed")
			return
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if _, err := discoverMCPTools(probeCtx, server.Url, server.AuthInjection, creds); err != nil {
		writeProto(w, http.StatusOK, &airlockv1.TestCredentialResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.TestCredentialResponse{
		Success: true,
		Message: "tools/list succeeded",
	})
}

// RevokeMCPOAuthApp handles DELETE /api/v1/agents/{agentID}/mcp-servers/{slug}/credentials/oauth-app.
// Wipes the OAuth app config (client_id + client_secret) AND the credentials
// that belong to it (existing tokens are tied to the old client_id at the
// provider — they'd 401 the moment they're used). Used by:
//   - "Re-register client" (oauth_discovery): clears the DCR'd client so
//     the next Authorize call re-DCRs against the registration_endpoint.
//   - "Edit OAuth app" (oauth): clears the pasted credentials so the
//     operator can paste new ones without UI ambiguity.
func (h *credentialHandler) RevokeMCPOAuthApp(w http.ResponseWriter, r *http.Request) {
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
	if err := q.ClearMCPServerOAuthApp(ctx, dbq.ClearMCPServerOAuthAppParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	}); err != nil {
		h.logger.Error("revoke MCP OAuth app failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to revoke OAuth app")
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

	srvRef := "mcp/" + pgUUID(server.ID).String()
	encClientID, err := h.encryptor.Put(ctx, srvRef+"/client_id", req.ClientId)
	if err != nil {
		h.logger.Error("encrypt client_id failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}
	encClientSecret, err := h.encryptor.Put(ctx, srvRef+"/client_secret", req.ClientSecret)
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

	// Reauthorize semantics: any pre-existing credentials are stale by
	// the time we redirect to the provider — the new code/refresh-token
	// pair from this flow is what counts. Clearing here means there's
	// no window where DB shows authorized=true but the actual tokens
	// are gone, and it lets a single "Authorize" button work for both
	// first-time and switch-account flows. No-op when already empty.
	if err := q.ClearMCPServerCredentials(ctx, dbq.ClearMCPServerCredentialsParams{
		AgentID: toPgUUID(agentID),
		Slug:    req.Slug,
	}); err != nil {
		h.logger.Error("clear stale MCP credentials failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to clear stale credentials")
		return
	}

	// Lazy URL re-discovery (oauth_discovery only): if any of the three
	// discovery URLs is missing — for instance, a previous sync wrote
	// empty values back over a populated row — re-run RFC 8414 discovery
	// before proceeding. Independent of DCR: even agents with a working
	// client_id need auth_url + token_url to authorize and refresh.
	needsDiscovery := server.AuthMode == "oauth_discovery" &&
		(server.AuthUrl == "" || server.TokenUrl == "" ||
			(server.ClientID == "" && server.RegistrationEndpoint == ""))
	if needsDiscovery {
		result, derr := discoverMCPAuth(ctx, server.Url)
		if derr != nil {
			h.logger.Warn("MCP discovery retry failed", zap.String("slug", req.Slug), zap.Error(derr))
			writeError(w, http.StatusBadRequest, "OAuth discovery failed: "+derr.Error()+
				". The server's RFC 8414 metadata is unreachable or malformed; switch this MCP server's auth_mode to `oauth` and paste credentials manually.")
			return
		}
		// Prefer fresh values; fall back to the existing row value when
		// discovery returned empty for a particular field (one-off
		// metadata gaps shouldn't flap a known-good URL).
		if result.AuthorizationURL != "" {
			server.AuthUrl = result.AuthorizationURL
		}
		if result.TokenURL != "" {
			server.TokenUrl = result.TokenURL
		}
		if result.RegistrationEndpoint != "" {
			server.RegistrationEndpoint = result.RegistrationEndpoint
		}
		if err := q.UpdateMCPServerDiscovery(ctx, dbq.UpdateMCPServerDiscoveryParams{
			AgentID:              toPgUUID(agentID),
			Slug:                 req.Slug,
			AuthUrl:              server.AuthUrl,
			TokenUrl:             server.TokenUrl,
			RegistrationEndpoint: server.RegistrationEndpoint,
		}); err != nil {
			h.logger.Error("persist re-discovery failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to persist discovery result")
			return
		}
	}

	// Lazy DCR for oauth_discovery: when no client_id is stored, register
	// one against the server's RFC 7591 endpoint instead of asking the
	// operator to paste credentials.
	if server.ClientID == "" && server.AuthMode == "oauth_discovery" {
		if server.RegistrationEndpoint == "" {
			writeError(w, http.StatusBadRequest,
				"server does not advertise an RFC 7591 registration endpoint. Switch this MCP server's auth_mode to `oauth` and paste credentials manually.")
			return
		}

		callbackURL := h.publicURL + "/api/v1/credentials/oauth/callback"
		dcr, derr := oauth.RegisterClient(ctx, mcpHTTPClient, server.RegistrationEndpoint, "airlock:"+server.Name, callbackURL, server.Scopes)
		if derr != nil {
			h.logger.Warn("MCP DCR failed", zap.String("slug", req.Slug), zap.Error(derr))
			writeError(w, http.StatusBadRequest,
				"dynamic client registration failed: "+derr.Error()+
					". Switch this MCP server's auth_mode to `oauth` and paste credentials manually.")
			return
		}

		srvRef := "mcp/" + pgUUID(server.ID).String()
		encClientID, err := h.encryptor.Put(ctx, srvRef+"/client_id", dcr.ClientID)
		if err != nil {
			h.logger.Error("encrypt DCR client_id failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "encryption failed")
			return
		}
		encClientSecret, err := h.encryptor.Put(ctx, srvRef+"/client_secret", dcr.ClientSecret)
		if err != nil {
			h.logger.Error("encrypt DCR client_secret failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "encryption failed")
			return
		}
		if err := q.UpdateMCPServerOAuthApp(ctx, dbq.UpdateMCPServerOAuthAppParams{
			AgentID:      toPgUUID(agentID),
			Slug:         req.Slug,
			ClientID:     encClientID,
			ClientSecret: encClientSecret,
		}); err != nil {
			h.logger.Error("persist DCR client failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to persist registered client")
			return
		}
		server.ClientID = encClientID
	}

	if server.ClientID == "" {
		writeError(w, http.StatusBadRequest, "OAuth app not configured. Set client_id and client_secret first.")
		return
	}

	clientID, err := h.encryptor.Get(ctx, "mcp/"+pgUUID(server.ID).String()+"/client_id", server.ClientID)
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

	encVerifier, err := h.encryptor.Put(ctx, "oauth_state/"+state+"/code_verifier", verifier)
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
