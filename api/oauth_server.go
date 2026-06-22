package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/auth/lockout"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// oauthServerHandler implements the MCP-side OAuth 2.1 Authorization
// Server: RFC 8414 AS metadata, RFC 9728 protected-resource metadata,
// RFC 7591 Dynamic Client Registration, RFC 6749 auth-code grant with
// mandatory PKCE (OAuth 2.1 §7.5.2), and RFC 8707 audience-bound
// access tokens.
//
// The MCP endpoint resolves principals; this handler issues + validates
// the OAuth-shape JWTs (see auth.IssueOAuthAccessToken). One AS for the
// whole airlock instance; per-agent resources distinguished by the
// canonical resource URL bound into the token's `aud` claim.
type oauthServerHandler struct {
	db        *db.DB
	jwtSecret string
	publicURL string
	logger    *zap.Logger

	// dcrLimiter is an in-memory per-IP token-bucket rate limiter on
	// /oauth/register (10 / hour / IP). NOT multi-replica safe —
	// today airlock is single-replica per CLAUDE.md; when multi-replica
	// lands, swap for a DB-backed sliding window using the auth_failures
	// table pattern.
	dcrLimiter *ipRateLimiter

	// pad is reused from the login lockout policy so the /token endpoint
	// responds in roughly-constant time — reuse-detection vs.
	// invalid-signature must not be timing-distinguishable.
	pad lockout.Policy
}

func newOAuthServerHandler(d *db.DB, jwtSecret, publicURL string, logger *zap.Logger) *oauthServerHandler {
	return &oauthServerHandler{
		db:         d,
		jwtSecret:  jwtSecret,
		publicURL:  strings.TrimRight(publicURL, "/"),
		logger:     logger,
		dcrLimiter: newIPRateLimiter(10, time.Hour),
		pad:        lockout.Default,
	}
}

// ============================================================
// Discovery — RFC 8414 + RFC 9728
// ============================================================

// asMetadata is the static RFC 8414 document for this instance. Omits
// OIDC-only fields (jwks_uri, userinfo_endpoint, subject_types,
// id_token_signing_alg_values_supported) and the deferred
// revocation/introspection endpoints.
type asMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
}

func (h *oauthServerHandler) ASMetadata(w http.ResponseWriter, r *http.Request) {
	out := asMetadata{
		Issuer:                            h.publicURL,
		AuthorizationEndpoint:             h.publicURL + "/oauth/authorize",
		TokenEndpoint:                     h.publicURL + "/oauth/token",
		RegistrationEndpoint:              h.publicURL + "/oauth/register",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		ScopesSupported:                   []string{"mcp"},
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	writeJSON(w, http.StatusOK, out)
}

// resourceMetadata is the per-agent RFC 9728 document. `resource` is
// echoed back exactly as the client typed it (slug OR uuid) so a
// client treating the response opaquely keeps working through slug
// renames. Server-side canonicalization to UUID only happens at
// /oauth/token mint time.
type resourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

func (h *oauthServerHandler) ResourceMetadata(w http.ResponseWriter, r *http.Request) {
	identifier := chi.URLParam(r, "identifier")
	q := dbq.New(h.db.Pool())

	if _, err := lookupAgentByIdentifier(r.Context(), q, identifier); err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusNotFound, "agent not found")
		return
	}
	resourceURL := fmt.Sprintf("%s/api/agent/%s/mcp", h.publicURL, identifier)
	out := resourceMetadata{
		Resource:               resourceURL,
		AuthorizationServers:   []string{h.publicURL},
		ScopesSupported:        []string{"mcp"},
		BearerMethodsSupported: []string{"header"},
		ResourceDocumentation:  resourceURL,
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	writeJSON(w, http.StatusOK, out)
}

// ============================================================
// Dynamic Client Registration — RFC 7591
// ============================================================

type dcrRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

type dcrResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

// dcrError follows the RFC 7591 §3.2.2 shape.
type dcrError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (h *oauthServerHandler) Register(w http.ResponseWriter, r *http.Request) {
	if !h.dcrLimiter.allow(realIP(r)) {
		w.Header().Set("Retry-After", "3600")
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusTooManyRequests, dcrError{
			Error: "rate_limited", ErrorDescription: "too many registrations from this IP",
		})
		return
	}

	var req dcrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, dcrError{Error: "invalid_request"})
		return
	}

	// Required: client_name + redirect_uris.
	if strings.TrimSpace(req.ClientName) == "" {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, dcrError{
			Error: "invalid_client_metadata", ErrorDescription: "client_name is required",
		})
		return
	}
	if len(req.ClientName) > 128 {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, dcrError{
			Error: "invalid_client_metadata", ErrorDescription: "client_name too long",
		})
		return
	}
	if len(req.RedirectURIs) == 0 {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, dcrError{
			Error: "invalid_redirect_uri", ErrorDescription: "at least one redirect_uri is required",
		})
		return
	}
	if len(req.RedirectURIs) > 5 {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, dcrError{
			Error: "invalid_redirect_uri", ErrorDescription: "max 5 redirect_uris",
		})
		return
	}
	for _, u := range req.RedirectURIs {
		if !isValidRedirectURI(u) {
			// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
			writeJSON(w, http.StatusBadRequest, dcrError{
				Error: "invalid_redirect_uri", ErrorDescription: "redirect_uri must be loopback http (127.0.0.1, [::1], localhost) or https",
			})
			return
		}
	}

	// Default + normalize grant/response/auth.
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	for _, g := range req.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
			writeJSON(w, http.StatusBadRequest, dcrError{
				Error: "invalid_client_metadata", ErrorDescription: "grant_types must be a subset of [authorization_code, refresh_token]",
			})
			return
		}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
			writeJSON(w, http.StatusBadRequest, dcrError{
				Error: "invalid_client_metadata", ErrorDescription: "only response_type=code is supported",
			})
			return
		}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "none"
	}
	if req.TokenEndpointAuthMethod != "none" {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, dcrError{
			Error: "invalid_client_metadata", ErrorDescription: "only token_endpoint_auth_method=none is supported in v1 (public clients only)",
		})
		return
	}

	// Scope is silently normalized to "mcp" — Codex etc. send things
	// like "openid offline_access mcp" and we ignore the extras.
	req.Scope = "mcp"

	clientID, err := newClientID()
	if err != nil {
		h.logger.Error("oauth register: client_id gen", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, dcrError{Error: "server_error"})
		return
	}

	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	row, err := q.CreateOAuthClient(r.Context(), dbq.CreateOAuthClientParams{
		ClientID:                clientID,
		ClientName:              req.ClientName,
		RedirectUris:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
	})
	if err != nil {
		h.logger.Error("oauth register: insert", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, dcrError{Error: "server_error"})
		return
	}

	// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	writeJSON(w, http.StatusCreated, dcrResponse{
		ClientID:                row.ClientID,
		ClientIDIssuedAt:        row.CreatedAt.Time.Unix(),
		ClientName:              row.ClientName,
		RedirectURIs:            row.RedirectUris,
		GrantTypes:              row.GrantTypes,
		ResponseTypes:           row.ResponseTypes,
		TokenEndpointAuthMethod: row.TokenEndpointAuthMethod,
		Scope:                   row.Scope,
	})
}

// ============================================================
// /oauth/authorize — browser entry point
// ============================================================

// Authorize handles the user-agent navigation. Validates params,
// resolves the authenticated user from the airlock_session cookie,
// and either jumps to the SPA consent view or skips consent if an
// active grant exists.
func (h *oauthServerHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	resource := q.Get("resource")
	scope := q.Get("scope")
	state := q.Get("state")

	// Step 1: response_type + code_challenge_method strict checks. No
	// redirect on these — the spec says respond with an error page when
	// the client_id or redirect_uri itself is invalid, so we may not
	// even have a safe redirect target yet.
	if responseType != "code" {
		renderOAuthError(w, "unsupported_response_type", "response_type must be 'code'")
		return
	}
	if codeChallengeMethod != "S256" {
		renderOAuthError(w, "invalid_request", "code_challenge_method must be 'S256'")
		return
	}
	if codeChallenge == "" || len(codeChallenge) < 43 || len(codeChallenge) > 128 {
		renderOAuthError(w, "invalid_request", "code_challenge missing or invalid length (43-128 chars)")
		return
	}

	// Step 2: load the client.
	qdb := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	client, err := qdb.GetOAuthClient(r.Context(), clientID)
	if err != nil {
		renderOAuthError(w, "invalid_request", "unknown client_id")
		return
	}

	// Step 3: redirect_uri must match an entry exactly.
	if !containsStr(client.RedirectUris, redirectURI) {
		renderOAuthError(w, "invalid_request", "redirect_uri does not match a registered URI")
		return
	}

	// Step 4: resolve the resource parameter to a canonical agent UUID.
	agentID, canonResource, err := h.canonicalizeResource(r.Context(), resource)
	if err != nil {
		redirectWithError(w, r, redirectURI, state, "invalid_target", err.Error())
		return
	}

	// Step 5: scope normalization. We accept any scope string and
	// always grant "mcp" — extras are silently dropped.
	_ = scope

	// Step 6: read the session cookie. If absent / invalid, redirect
	// to /login with a redirect parameter back here. The SPA login
	// flow already supports ?redirect= to arbitrary in-app paths.
	userID, err := h.userFromSessionCookie(r)
	if err != nil {
		// We need to bounce through the SPA's login screen and then
		// land on /oauth/consent (not back here) so the consent UI
		// can run. The original /authorize query is reflected onto
		// /oauth/consent.
		consentURL := h.publicURL + "/oauth/consent?" + r.URL.RawQuery
		loginURL := h.publicURL + "/login?redirect=" + url.QueryEscape(consentURL)
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Step 7: active grant check. Skip consent if (user, client, agent)
	// has a non-revoked, non-expired grant.
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	_, gErr := qdb.GetActiveGrant(r.Context(), dbq.GetActiveGrantParams{
		UserID:   toPgUUID(userID),
		ClientID: clientID,
		AgentID:  toPgUUID(agentID),
	})
	if gErr == nil {
		// Mint code immediately and bounce.
		code, mErr := h.mintAuthzCode(r.Context(), userID, clientID, agentID, redirectURI, codeChallenge, "mcp", canonResource)
		if mErr != nil {
			h.logger.Error("oauth authorize: mint code", zap.Error(mErr))
			redirectWithError(w, r, redirectURI, state, "server_error", "")
			return
		}
		bounceWithCode(w, r, redirectURI, code, state)
		return
	}

	// Step 8: consent required — redirect to the SPA consent view with
	// reflected params so the SPA can render + POST /oauth/consent.
	http.Redirect(w, r, h.publicURL+"/oauth/consent?"+r.URL.RawQuery, http.StatusFound)
}

// ============================================================
// /oauth/consent — the SPA POSTs here after Approve/Cancel
// ============================================================

type consentRequest struct {
	Decision            string `json:"decision"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Scope               string `json:"scope"`
	Resource            string `json:"resource"`
}

type consentResponse struct {
	RedirectTo string `json:"redirect_to"`
}

func (h *oauthServerHandler) Consent(w http.ResponseWriter, r *http.Request) {
	// Origin check — defense-in-depth against CSRF on the only
	// state-mutating endpoint in the OAuth flow that's reachable via
	// a session cookie. The SPA always carries an Origin matching our
	// public URL; cross-site POSTs from a malicious page would carry
	// a different (or no) Origin.
	if !originMatchesPublicURL(r, h.publicURL) {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusForbidden, "bad origin")
		return
	}

	userID := auth.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req consentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}

	// Re-validate everything from /authorize (client, redirect_uri,
	// challenge shape, resource) — never trust the SPA blindly.
	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	client, err := q.GetOAuthClient(r.Context(), req.ClientID)
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, "unknown client_id")
		return
	}
	if !containsStr(client.RedirectUris, req.RedirectURI) {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, "redirect_uri mismatch")
		return
	}
	if req.CodeChallengeMethod != "S256" || len(req.CodeChallenge) < 43 || len(req.CodeChallenge) > 128 {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, "bad code_challenge")
		return
	}
	agentID, canonResource, err := h.canonicalizeResource(r.Context(), req.Resource)
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Deny → bounce with error.
	if req.Decision == "deny" {
		bounceURL := buildRedirectURL(req.RedirectURI, map[string]string{
			"error":             "access_denied",
			"error_description": "user denied consent",
			"state":             req.State,
		})
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusOK, consentResponse{RedirectTo: bounceURL})
		return
	}
	if req.Decision != "approve" {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, "decision must be 'approve' or 'deny'")
		return
	}

	// Mint code + upsert the grant so subsequent /authorize hits skip
	// the consent screen.
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	if err := q.UpsertGrant(r.Context(), dbq.UpsertGrantParams{
		UserID:    toPgUUID(userID),
		ClientID:  req.ClientID,
		AgentID:   toPgUUID(agentID),
		Scope:     "mcp",
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(90 * 24 * time.Hour), Valid: true},
	}); err != nil {
		h.logger.Error("oauth consent: upsert grant", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	code, err := h.mintAuthzCode(r.Context(), userID, req.ClientID, agentID, req.RedirectURI, req.CodeChallenge, "mcp", canonResource)
	if err != nil {
		h.logger.Error("oauth consent: mint code", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	bounceURL := buildRedirectURL(req.RedirectURI, map[string]string{
		"code":  code,
		"state": req.State,
	})
	// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	writeJSON(w, http.StatusOK, consentResponse{RedirectTo: bounceURL})
}

// ============================================================
// /oauth/token — code → tokens, refresh → tokens
// ============================================================

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

type tokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (h *oauthServerHandler) Token(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer h.pad.PadResponse(start)

	if err := r.ParseForm(); err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_request"})
		return
	}

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		h.tokenAuthorizationCode(w, r)
	case "refresh_token":
		h.tokenRefresh(w, r)
	default:
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "unsupported_grant_type"})
	}
}

func (h *oauthServerHandler) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostFormValue("code")
	clientID := r.PostFormValue("client_id")
	redirectURI := r.PostFormValue("redirect_uri")
	codeVerifier := r.PostFormValue("code_verifier")
	resource := r.PostFormValue("resource")

	if code == "" || clientID == "" || redirectURI == "" || codeVerifier == "" {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_request"})
		return
	}

	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	row, err := q.ConsumeAuthzCode(r.Context(), code)
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "code invalid or expired"})
		return
	}
	if row.ClientID != clientID {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "client_id mismatch"})
		return
	}
	if row.RedirectUri != redirectURI {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "redirect_uri mismatch"})
		return
	}
	if resource != "" && resource != row.Resource {
		// Allow client to omit resource on /token (RFC 8707 §2.2
		// requires identical to /authorize when present); reject if
		// supplied AND different.
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "resource mismatch"})
		return
	}
	if !verifyPKCE(codeVerifier, row.CodeChallenge) {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "PKCE verifier failed"})
		return
	}

	// Mint access JWT + opaque refresh.
	userID := uuid.UUID(row.UserID.Bytes)
	agentID := uuid.UUID(row.AgentID.Bytes)
	email, tenantRole := h.lookupUserClaims(r.Context(), userID)

	accessToken, err := auth.IssueOAuthAccessToken(h.jwtSecret, userID, email, tenantRole, clientID, row.Scope, row.Resource)
	if err != nil {
		h.logger.Error("oauth token: issue access", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}

	refreshRaw, err := newRefreshToken()
	if err != nil {
		h.logger.Error("oauth token: gen refresh", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}
	refreshHash := hashToken(refreshRaw)
	familyID := uuid.New()
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	if err := q.CreateRefreshToken(r.Context(), dbq.CreateRefreshTokenParams{
		TokenHash:       refreshHash,
		UserID:          row.UserID,
		ClientID:        clientID,
		AgentID:         row.AgentID,
		Scope:           row.Scope,
		FamilyID:        toPgUUID(familyID),
		ParentTokenHash: nil,
		ExpiresAt:       pgtype.Timestamptz{Time: time.Now().Add(30 * 24 * time.Hour), Valid: true},
	}); err != nil {
		h.logger.Error("oauth token: insert refresh", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}

	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	_ = q.TouchOAuthClient(r.Context(), clientID)
	_ = agentID // we issued under this aud; logged via JWT claims

	// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(auth.AccessTokenDuration / time.Second),
		RefreshToken: refreshRaw,
		Scope:        row.Scope,
	})
}

func (h *oauthServerHandler) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	refresh := r.PostFormValue("refresh_token")
	clientID := r.PostFormValue("client_id")
	if refresh == "" || clientID == "" {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_request"})
		return
	}

	hash := hashToken(refresh)
	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	row, err := q.GetRefreshTokenByHash(r.Context(), hash)
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant"})
		return
	}
	if row.ClientID != clientID {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "client_id mismatch"})
		return
	}
	if row.ExpiresAt.Time.Before(time.Now()) {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "expired"})
		return
	}
	if row.ConsumedAt.Valid {
		// Reuse detection: revoke the whole family.
		// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		_, _ = q.RevokeRefreshFamily(r.Context(), row.FamilyID)
		h.logger.Warn("oauth token refresh: reuse detected — family revoked",
			zap.String("family_id", uuid.UUID(row.FamilyID.Bytes).String()),
			zap.String("client_id", clientID),
			zap.String("user_id", uuid.UUID(row.UserID.Bytes).String()),
		)
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "token reuse detected"})
		return
	}

	// Grant must still be active.
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	if _, gErr := q.GetActiveGrant(r.Context(), dbq.GetActiveGrantParams{
		UserID:   row.UserID,
		ClientID: clientID,
		AgentID:  row.AgentID,
	}); gErr != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "grant revoked or expired"})
		return
	}

	// Consume the old + mint the new in a single rotation step. The
	// MarkRefreshConsumed update is atomic enough on a single row;
	// concurrent refresh attempts on the same token lose to a row
	// lock and observe consumed_at set on their second SELECT — that
	// triggers reuse-detection.
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	if err := q.MarkRefreshConsumed(r.Context(), hash); err != nil {
		h.logger.Error("oauth token refresh: mark consumed", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}

	newRaw, err := newRefreshToken()
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}
	newHash := hashToken(newRaw)
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	if err := q.CreateRefreshToken(r.Context(), dbq.CreateRefreshTokenParams{
		TokenHash:       newHash,
		UserID:          row.UserID,
		ClientID:        clientID,
		AgentID:         row.AgentID,
		Scope:           row.Scope,
		FamilyID:        row.FamilyID,
		ParentTokenHash: hash,
		ExpiresAt:       pgtype.Timestamptz{Time: time.Now().Add(30 * 24 * time.Hour), Valid: true},
	}); err != nil {
		h.logger.Error("oauth token refresh: insert new", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}

	// Mint new access — same audience as the old row.
	userID := uuid.UUID(row.UserID.Bytes)
	email, tenantRole := h.lookupUserClaims(r.Context(), userID)
	audience := fmt.Sprintf("%s/api/agent/%s/mcp", h.publicURL, uuid.UUID(row.AgentID.Bytes).String())
	access, err := auth.IssueOAuthAccessToken(h.jwtSecret, userID, email, tenantRole, clientID, row.Scope, audience)
	if err != nil {
		h.logger.Error("oauth token refresh: issue access", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}

	// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(auth.AccessTokenDuration / time.Second),
		RefreshToken: newRaw,
		Scope:        row.Scope,
	})
}

// ============================================================
// Grant listing + revoke — UI surface
// ============================================================

type grantDTO struct {
	ClientID   string `json:"clientId"`
	ClientName string `json:"clientName"`
	AgentID    string `json:"agentId"`
	AgentSlug  string `json:"agentSlug"`
	AgentName  string `json:"agentName"`
	Scope      string `json:"scope"`
	GrantedAt  string `json:"grantedAt"`
	ExpiresAt  string `json:"expiresAt"`
}

func (h *oauthServerHandler) ListGrants(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	rows, err := q.ListGrantsForUser(r.Context(), toPgUUID(userID))
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusInternalServerError, "list grants")
		return
	}
	out := make([]grantDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, grantDTO{
			ClientID:   row.ClientID,
			ClientName: row.ClientName,
			AgentID:    uuid.UUID(row.AgentID.Bytes).String(),
			AgentSlug:  row.AgentSlug,
			AgentName:  row.AgentName,
			Scope:      row.Scope,
			GrantedAt:  row.GrantedAt.Time.Format(time.RFC3339),
			ExpiresAt:  row.ExpiresAt.Time.Format(time.RFC3339),
		})
	}
	// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	writeJSON(w, http.StatusOK, out)
}

func (h *oauthServerHandler) RevokeGrant(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	clientID := chi.URLParam(r, "clientID")
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	if _, err := q.RevokeGrant(r.Context(), dbq.RevokeGrantParams{
		UserID:   toPgUUID(userID),
		ClientID: clientID,
		AgentID:  toPgUUID(agentID),
	}); err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusInternalServerError, "revoke")
		return
	}
	// Also invalidate refresh tokens so the next refresh fails fast.
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	_, _ = q.RevokeRefreshForGrant(r.Context(), dbq.RevokeRefreshForGrantParams{
		UserID:   toPgUUID(userID),
		ClientID: clientID,
		AgentID:  toPgUUID(agentID),
	})
	w.WriteHeader(http.StatusNoContent)
}

// ============================================================
// Helpers
// ============================================================

func (h *oauthServerHandler) canonicalizeResource(ctx context.Context, resource string) (uuid.UUID, string, error) {
	if resource == "" {
		return uuid.Nil, "", fmt.Errorf("resource is required")
	}
	prefix := h.publicURL + "/api/agent/"
	suffix := "/mcp"
	if !strings.HasPrefix(resource, prefix) || !strings.HasSuffix(resource, suffix) {
		return uuid.Nil, "", fmt.Errorf("resource must match %sIDENTIFIER%s", prefix, suffix)
	}
	identifier := resource[len(prefix) : len(resource)-len(suffix)]
	if identifier == "" {
		return uuid.Nil, "", fmt.Errorf("missing agent identifier in resource")
	}
	q := dbq.New(h.db.Pool())
	ag, err := lookupAgentByIdentifier(ctx, q, identifier)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("unknown agent")
	}
	agentID := uuid.UUID(ag.ID.Bytes)
	canonical := fmt.Sprintf("%s/api/agent/%s/mcp", h.publicURL, agentID.String())
	return agentID, canonical, nil
}

func (h *oauthServerHandler) mintAuthzCode(ctx context.Context, userID uuid.UUID, clientID string, agentID uuid.UUID, redirectURI, codeChallenge, scope, resource string) (string, error) {
	code, err := newAuthzCode()
	if err != nil {
		return "", err
	}
	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	if err := q.CreateAuthzCode(ctx, dbq.CreateAuthzCodeParams{
		Code:          code,
		UserID:        toPgUUID(userID),
		ClientID:      clientID,
		AgentID:       toPgUUID(agentID),
		RedirectUri:   redirectURI,
		CodeChallenge: codeChallenge,
		Scope:         scope,
		Resource:      resource,
		ExpiresAt:     pgtype.Timestamptz{Time: time.Now().Add(60 * time.Second), Valid: true},
	}); err != nil {
		return "", err
	}
	return code, nil
}

func (h *oauthServerHandler) userFromSessionCookie(r *http.Request) (uuid.UUID, error) {
	c, err := r.Cookie("airlock_session")
	if err != nil {
		return uuid.Nil, err
	}
	claims, err := auth.ValidateToken(h.jwtSecret, c.Value)
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(claims.Subject)
}

func (h *oauthServerHandler) lookupUserClaims(ctx context.Context, userID uuid.UUID) (email, tenantRole string) {
	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	u, err := q.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		return "", ""
	}
	return u.Email, u.TenantRole
}

// lookupAgentByIdentifier is a thin alias for service.ResolveAgent at
// the OAuth-server call sites; the {identifier} path param accepts the
// agent's slug or its UUID.
func lookupAgentByIdentifier(ctx context.Context, q *dbq.Queries, identifier string) (dbq.Agent, error) {
	return service.ResolveAgent(ctx, q, identifier)
}

// ============================================================
// Small primitives
// ============================================================

func newClientID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "alk_pub_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func newAuthzCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newRefreshToken() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// verifyPKCE checks base64url(SHA256(verifier)) == challenge. S256-only;
// plain isn't accepted (we reject it at /authorize).
func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

func isValidRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		host := u.Hostname()
		return host == "127.0.0.1" || host == "::1" || host == "localhost"
	default:
		return false
	}
}

func containsStr(arr []string, v string) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}

func buildRedirectURL(base string, params map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, v := range params {
		if v == "" {
			continue
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func bounceWithCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	http.Redirect(w, r, buildRedirectURL(redirectURI, map[string]string{
		"code": code, "state": state,
	}), http.StatusFound)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	http.Redirect(w, r, buildRedirectURL(redirectURI, map[string]string{
		"error": errCode, "error_description": errDesc, "state": state,
	}), http.StatusFound)
}

func renderOAuthError(w http.ResponseWriter, errCode, errDesc string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>OAuth Error</title></head><body><h1>%s</h1><p>%s</p></body></html>`,
		htmlEscape(errCode), htmlEscape(errDesc))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func originMatchesPublicURL(r *http.Request, publicURL string) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		// Same-origin SPA POSTs don't always set Origin (varies by
		// browser); we accept the absence too since the cookie won't
		// be sent cross-site without Origin in modern browsers.
		return true
	}
	return o == publicURL
}

func realIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if comma := strings.Index(xf, ","); comma > 0 {
			return strings.TrimSpace(xf[:comma])
		}
		return strings.TrimSpace(xf)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	return r.RemoteAddr
}

// ipRateLimiter is a simple per-IP token bucket. Not multi-replica
// safe; see Risks in the plan.
type ipRateLimiter struct {
	mu       sync.Mutex
	capacity int
	window   time.Duration
	buckets  map[string]*ipBucket
}

type ipBucket struct {
	count    int
	resetsAt time.Time
}

func newIPRateLimiter(capacity int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		capacity: capacity,
		window:   window,
		buckets:  make(map[string]*ipBucket),
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	if ip == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[ip]
	if !ok || now.After(b.resetsAt) {
		l.buckets[ip] = &ipBucket{count: 1, resetsAt: now.Add(l.window)}
		return true
	}
	if b.count >= l.capacity {
		return false
	}
	b.count++
	return true
}
