package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"context"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type credentialHandler struct {
	db          *db.DB
	encryptor   *crypto.Encryptor
	oauthClient *oauth.Client
	publicURL   string
	logger      *zap.Logger
	// dispatcher is used by OAuthCallback to push /refresh into a running
	// agent container after MCP auth completes so its cached system prompt
	// + MCP schemas pick up the new tools without a container restart.
	// May be nil in tests; the OAuth callback then skips the push.
	dispatcher *trigger.Dispatcher
}

// --- Task 4a: Set OAuth app credentials ---

// SetOAuthApp handles PUT /api/v1/agents/{agentID}/credentials/{slug}/oauth-app.
func (h *credentialHandler) SetOAuthApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	// Verify agent belongs to authenticated user.
	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	conn, err := q.GetConnectionForOAuth(ctx, dbq.GetConnectionForOAuthParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		h.logger.Error("get connection failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get connection")
		return
	}
	if conn.AuthMode != "oauth" {
		writeError(w, http.StatusBadRequest, "connection is not OAuth — use API key endpoint")
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

	if err := q.UpdateConnectionOAuthApp(ctx, dbq.UpdateConnectionOAuthAppParams{
		AgentID:      toPgUUID(agentID),
		Slug:         slug,
		ClientID:     encClientID,
		ClientSecret: encClientSecret,
	}); err != nil {
		h.logger.Error("update oauth app failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to update OAuth app")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.CredentialStatusResponse{
		Slug:       slug,
		Name:       conn.Name,
		AuthMode:   "oauth",
		Authorized: false,
	})
}

// --- Task 4b: OAuth start ---

// OAuthStart handles POST /api/v1/credentials/oauth/start.
func (h *credentialHandler) OAuthStart(w http.ResponseWriter, r *http.Request) {
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
	conn, err := q.GetConnectionForOAuth(ctx, dbq.GetConnectionForOAuthParams{
		AgentID: toPgUUID(agentID),
		Slug:    req.Slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		h.logger.Error("get connection failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get connection")
		return
	}
	if conn.AuthMode != "oauth" {
		writeError(w, http.StatusBadRequest, "connection is not OAuth")
		return
	}
	if conn.ClientID == "" {
		writeError(w, http.StatusBadRequest, "OAuth app not configured. Set client_id and client_secret first.")
		return
	}

	clientID, err := h.encryptor.Decrypt(conn.ClientID)
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
		SourceType:   "connection",
	}); err != nil {
		h.logger.Error("create oauth state failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to save state")
		return
	}

	callbackURL := h.publicURL + "/api/v1/credentials/oauth/callback"
	authURL, err := h.oauthClient.BuildAuthURL(conn.AuthUrl, clientID, callbackURL, state, challenge, conn.Scopes)
	if err != nil {
		h.logger.Error("build auth URL failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to build authorization URL")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.OAuthStartResponse{
		AuthorizeUrl: authURL,
	})
}

// --- Task 4c: OAuth callback ---

// OAuthCallback handles GET /api/v1/credentials/oauth/callback.
// Called by the OAuth provider after user authorizes — outside JWT middleware.
func (h *credentialHandler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state parameter", http.StatusBadRequest)
		return
	}

	q := dbq.New(h.db.Pool())
	oauthState, err := q.GetOAuthState(ctx, state)
	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "invalid or expired state", http.StatusBadRequest)
			return
		}
		h.logger.Error("get oauth state failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	agentID := pgUUID(oauthState.AgentID)

	verifier, err := h.encryptor.Decrypt(oauthState.CodeVerifier)
	if err != nil {
		h.logger.Error("decrypt verifier failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Route to the right table based on source_type.
	var tokenURL, clientIDEnc, clientSecretEnc string
	if oauthState.SourceType == "mcp" {
		srv, err := q.GetMCPServerForOAuth(ctx, dbq.GetMCPServerForOAuthParams{
			AgentID: oauthState.AgentID,
			Slug:    oauthState.Slug,
		})
		if err != nil {
			h.logger.Error("get MCP server for callback failed", zap.Error(err))
			http.Error(w, "MCP server not found", http.StatusInternalServerError)
			return
		}
		tokenURL = srv.TokenUrl
		clientIDEnc = srv.ClientID
		clientSecretEnc = srv.ClientSecret
	} else {
		conn, err := q.GetConnectionForOAuth(ctx, dbq.GetConnectionForOAuthParams{
			AgentID: oauthState.AgentID,
			Slug:    oauthState.Slug,
		})
		if err != nil {
			h.logger.Error("get connection for callback failed", zap.Error(err))
			http.Error(w, "connection not found", http.StatusInternalServerError)
			return
		}
		tokenURL = conn.TokenUrl
		clientIDEnc = conn.ClientID
		clientSecretEnc = conn.ClientSecret
	}

	clientID, err := h.encryptor.Decrypt(clientIDEnc)
	if err != nil {
		h.logger.Error("decrypt client_id failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	clientSecret, err := h.encryptor.Decrypt(clientSecretEnc)
	if err != nil {
		h.logger.Error("decrypt client_secret failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	callbackURL := h.publicURL + "/api/v1/credentials/oauth/callback"
	tokenResp, err := h.oauthClient.ExchangeCode(ctx, tokenURL, code, verifier, callbackURL, clientID, clientSecret)
	if err != nil {
		h.logger.Error("token exchange failed", zap.Error(err))
		redirectURI := h.defaultRedirectURI(oauthState.RedirectUri, agentID)
		http.Redirect(w, r, redirectURI+"?error=exchange_failed&message="+err.Error(), http.StatusFound)
		return
	}

	encAccessToken, err := h.encryptor.Encrypt(tokenResp.AccessToken)
	if err != nil {
		h.logger.Error("encrypt access token failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var encRefreshToken string
	if tokenResp.RefreshToken != "" {
		encRefreshToken, err = h.encryptor.Encrypt(tokenResp.RefreshToken)
		if err != nil {
			h.logger.Error("encrypt refresh token failed", zap.Error(err))
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	var expiresAt pgtype.Timestamptz
	if tokenResp.ExpiresIn > 0 {
		expiresAt = pgtype.Timestamptz{Time: time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second), Valid: true}
	}

	// Store credentials in the right table.
	if oauthState.SourceType == "mcp" {
		if err := q.UpdateMCPServerCredentials(ctx, dbq.UpdateMCPServerCredentialsParams{
			AgentID:        oauthState.AgentID,
			Slug:           oauthState.Slug,
			Credentials:    encAccessToken,
			TokenExpiresAt: expiresAt,
			RefreshToken:   encRefreshToken,
		}); err != nil {
			h.logger.Error("store MCP credentials failed", zap.Error(err))
			http.Error(w, "failed to store credentials", http.StatusInternalServerError)
			return
		}
		// Now that the server is authorized, immediately discover its tools
		// and push the running agent to re-sync. Both steps are best-effort:
		// any failure here just means the agent picks up the new tools on
		// its next sync (next prompt boots a fresh container, or the
		// existing one re-syncs at startup after reap). The user shouldn't
		// be blocked from completing OAuth because of an internal hiccup.
		h.refreshMCPAfterAuth(ctx, agentID, oauthState.Slug, tokenResp.AccessToken)
	} else {
		if err := q.UpdateConnectionCredentials(ctx, dbq.UpdateConnectionCredentialsParams{
			AgentID:        oauthState.AgentID,
			Slug:           oauthState.Slug,
			Credentials:    encAccessToken,
			TokenExpiresAt: expiresAt,
			RefreshToken:   encRefreshToken,
		}); err != nil {
			h.logger.Error("store credentials failed", zap.Error(err))
			http.Error(w, "failed to store credentials", http.StatusInternalServerError)
			return
		}
	}

	_ = q.DeleteOAuthState(ctx, state)

	redirectURI := h.defaultRedirectURI(oauthState.RedirectUri, agentID)
	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// refreshMCPAfterAuth re-discovers tools for a freshly-authorized MCP server
// and pushes the running agent container to re-sync. All steps are
// best-effort: if discovery, persistence, or the /refresh push fails, we log
// and continue. The agent will pick up the new tools on its next sync (next
// container boot or scheduled re-sync), so degraded paths self-heal.
func (h *credentialHandler) refreshMCPAfterAuth(ctx context.Context, agentID uuid.UUID, slug, accessToken string) {
	q := dbq.New(h.db.Pool())
	srv, err := q.GetMCPServerBySlug(ctx, dbq.GetMCPServerBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		h.logger.Warn("refresh MCP: get server failed", zap.String("slug", slug), zap.Error(err))
		return
	}

	tools, err := discoverMCPTools(ctx, srv.Url, accessToken)
	if err != nil {
		h.logger.Warn("refresh MCP: discovery failed", zap.String("slug", slug), zap.Error(err))
		// Don't return — we still want to ping the agent. Sync handler will
		// try discovery again with the stored credentials.
	} else {
		schemasJSON, _ := json.Marshal(tools)
		if err := q.UpdateMCPServerToolSchemas(ctx, dbq.UpdateMCPServerToolSchemasParams{
			AgentID:     toPgUUID(agentID),
			Slug:        slug,
			ToolSchemas: schemasJSON,
		}); err != nil {
			h.logger.Warn("refresh MCP: persist schemas failed", zap.String("slug", slug), zap.Error(err))
		}
	}

	if h.dispatcher == nil {
		return
	}
	if err := h.dispatcher.RefreshAgent(ctx, agentID); err != nil {
		h.logger.Warn("refresh MCP: agent /refresh failed", zap.String("agent", agentID.String()), zap.Error(err))
	}
}

// --- Task 4d: API key entry ---

// SetAPIKey handles POST /api/v1/agents/{agentID}/credentials/{slug}.
func (h *credentialHandler) SetAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	conn, err := q.GetConnectionBySlug(ctx, dbq.GetConnectionBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		h.logger.Error("get connection failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get connection")
		return
	}
	if conn.AuthMode == "oauth" {
		writeError(w, http.StatusBadRequest, "use OAuth flow for OAuth connections")
		return
	}

	encKey, err := h.encryptor.Encrypt(req.ApiKey)
	if err != nil {
		h.logger.Error("encrypt API key failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	if err := q.UpdateConnectionCredentials(ctx, dbq.UpdateConnectionCredentialsParams{
		AgentID:     toPgUUID(agentID),
		Slug:        slug,
		Credentials: encKey,
	}); err != nil {
		h.logger.Error("store API key failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to store API key")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.CredentialStatusResponse{
		Slug:       slug,
		Name:       conn.Name,
		AuthMode:   conn.AuthMode,
		Authorized: true,
	})
}

// --- Task 5a: List connections ---

// ListConnections handles GET /api/v1/agents/{agentID}/connections.
func (h *credentialHandler) ListConnections(w http.ResponseWriter, r *http.Request) {
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
	rows, err := q.ListConnectionsWithStatus(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list connections failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list connections")
		return
	}

	conns := make([]*airlockv1.ConnectionInfo, len(rows))
	for i, c := range rows {
		ci := &airlockv1.ConnectionInfo{
			Id:                pgUUID(c.ID).String(),
			Slug:              c.Slug,
			Name:              c.Name,
			Description:       c.Description,
			AuthMode:          c.AuthMode,
			Authorized:        c.Authorized,
			HasOauthApp:       c.HasOauthApp,
			SetupInstructions: c.SetupInstructions,
			AuthUrl:           buildCredentialAuthURL(h.publicURL, agentID, c.Slug, c.AuthMode),
		}
		if c.TokenExpiresAt.Valid {
			ci.TokenExpiresAt = timestamppb.New(c.TokenExpiresAt.Time)
		}
		conns[i] = ci
	}

	writeProto(w, http.StatusOK, &airlockv1.ListConnectionsResponse{
		Connections:      conns,
		OauthCallbackUrl: h.publicURL + "/api/v1/credentials/oauth/callback",
	})
}

// --- Task 5b: Credential status ---

// CredentialStatus handles GET /api/v1/agents/{agentID}/credentials/{slug}.
func (h *credentialHandler) CredentialStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	conn, err := q.GetConnectionWithCredentialStatus(ctx, dbq.GetConnectionWithCredentialStatusParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		h.logger.Error("get credential status failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get credential status")
		return
	}

	resp := &airlockv1.CredentialStatusResponse{
		Slug:       conn.Slug,
		Name:       conn.Name,
		AuthMode:   conn.AuthMode,
		Authorized: conn.Authorized,
	}
	if conn.TokenExpiresAt.Valid {
		resp.TokenExpiresAt = timestamppb.New(conn.TokenExpiresAt.Time)
	}

	writeProto(w, http.StatusOK, resp)
}

// --- Task 5c: Revoke credential ---

// RevokeCredential handles DELETE /api/v1/agents/{agentID}/credentials/{slug}.
func (h *credentialHandler) RevokeCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	if err := q.ClearConnectionCredentials(ctx, dbq.ClearConnectionCredentialsParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	}); err != nil {
		h.logger.Error("revoke credential failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to revoke credential")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Task 5d: Test credential ---

// TestCredential handles POST /api/v1/agents/{agentID}/credentials/{slug}/test.
func (h *credentialHandler) TestCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	conn, err := q.GetConnectionBySlug(ctx, dbq.GetConnectionBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		h.logger.Error("get connection failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to get connection")
		return
	}

	if conn.Credentials == "" {
		writeError(w, http.StatusBadRequest, "no credentials configured")
		return
	}

	// If no test_path, just verify credentials exist.
	if conn.TestPath == "" {
		resp := &airlockv1.TestCredentialResponse{Success: true, Message: "credentials configured"}
		if conn.AuthMode == "oauth" && conn.TokenExpiresAt.Valid && conn.TokenExpiresAt.Time.Before(time.Now()) {
			resp.Success = false
			resp.Message = "OAuth token has expired"
		}
		writeProto(w, http.StatusOK, resp)
		return
	}

	creds, err := h.encryptor.Decrypt(conn.Credentials)
	if err != nil {
		h.logger.Error("decrypt credentials failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	testURL := conn.BaseUrl + conn.TestPath
	upstream, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid test URL")
		return
	}
	injectAuth(upstream, conn.AuthInjection, creds)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(upstream)
	if err != nil {
		writeProto(w, http.StatusOK, &airlockv1.TestCredentialResponse{
			Success: false,
			Message: fmt.Sprintf("request failed: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := "OK"
	if resp.StatusCode >= 400 {
		msg = strings.TrimSpace(string(body))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
	}

	writeProto(w, http.StatusOK, &airlockv1.TestCredentialResponse{
		Success:    resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode: int32(resp.StatusCode),
		Message:    msg,
	})
}

// --- helpers ---

func (h *credentialHandler) resolveAgentSlug(r *http.Request) (agentID [16]byte, slug string, err error) {
	id, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		return id, "", fmt.Errorf("invalid agentID")
	}
	slug = chi.URLParam(r, "slug")
	if slug == "" {
		return id, "", fmt.Errorf("slug is required")
	}
	return id, slug, nil
}

func (h *credentialHandler) verifyAgentOwner(ctx context.Context, agentID [16]byte, r *http.Request) error {
	userID := auth.UserIDFromContext(r.Context())
	if userID == (uuid.UUID{}) {
		return fmt.Errorf("not authenticated")
	}

	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		return fmt.Errorf("agent not found")
	}

	if pgUUID(agent.UserID) != userID {
		return fmt.Errorf("not owner")
	}
	return nil
}

func (h *credentialHandler) defaultRedirectURI(stateRedirect string, agentID [16]byte) string {
	if stateRedirect != "" {
		return stateRedirect
	}
	return fmt.Sprintf("%s/agents/%s", h.publicURL, agentID)
}
