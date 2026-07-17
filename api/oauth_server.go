package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/auth/lockout"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

	// pad is reused from the login lockout policy so the /token endpoint
	// responds in roughly-constant time — reuse-detection vs.
	// invalid-signature must not be timing-distinguishable.
	pad lockout.Policy
}

func newOAuthServerHandler(d *db.DB, jwtSecret, publicURL string, logger *zap.Logger) *oauthServerHandler {
	if d == nil {
		panic("api: oauth server db is required")
	}
	if logger == nil {
		panic("api: oauth server logger is required")
	}
	if jwtSecret == "" {
		panic("api: oauth server JWT secret is required")
	}
	if publicURL == "" {
		panic("api: oauth server public URL is required")
	}
	return &oauthServerHandler{
		db:        d,
		jwtSecret: jwtSecret,
		publicURL: strings.TrimRight(publicURL, "/"),
		logger:    logger,
		pad:       lockout.Default,
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
	w.Header().Set("Cache-Control", "no-store")
	q := dbq.New(h.db.Pool())
	// RemoteAddr has already been rewritten by the trusted-proxy middleware.
	// Never inspect forwarding headers here; direct clients can spoof them.
	// airlockvet:allow-dbq reason: unauthenticated DCR rate limit is keyed by trusted normalized network identity
	allowed, err := q.AllowOAuthClientRegistration(r.Context(), lockout.NormalizeIP(r.RemoteAddr))
	if err != nil {
		h.logger.Error("oauth register: rate limit", zap.Error(err))
		// airlockvet:allow-writejson reason: RFC 7591 dynamic client registration errors use the standardized JSON shape
		writeJSON(w, http.StatusInternalServerError, dcrError{Error: "server_error"})
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", "3600")
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusTooManyRequests, dcrError{
			Error: "rate_limited", ErrorDescription: "too many registrations from this IP",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	defer r.Body.Close()
	var req dcrRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF {
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
	req.ClientName = strings.TrimSpace(req.ClientName)
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
	seenRedirects := make(map[string]struct{}, len(req.RedirectURIs))
	for _, u := range req.RedirectURIs {
		if !isValidRedirectURI(u) {
			// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
			writeJSON(w, http.StatusBadRequest, dcrError{
				Error: "invalid_redirect_uri", ErrorDescription: "redirect_uri must use https or an http loopback IP literal",
			})
			return
		}
		if _, exists := seenRedirects[u]; exists {
			// airlockvet:allow-writejson reason: RFC 7591 dynamic client registration errors use the standardized JSON shape
			writeJSON(w, http.StatusBadRequest, dcrError{Error: "invalid_redirect_uri", ErrorDescription: "redirect_uris must be unique"})
			return
		}
		seenRedirects[u] = struct{}{}
	}

	// Default + normalize grant/response/auth.
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.GrantTypes) > 2 {
		// airlockvet:allow-writejson reason: RFC 7591 dynamic client registration errors use the standardized JSON shape
		writeJSON(w, http.StatusBadRequest, dcrError{Error: "invalid_client_metadata", ErrorDescription: "too many grant_types"})
		return
	}
	seenGrants := make(map[string]struct{}, len(req.GrantTypes))
	for _, g := range req.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
			writeJSON(w, http.StatusBadRequest, dcrError{
				Error: "invalid_client_metadata", ErrorDescription: "grant_types must be a subset of [authorization_code, refresh_token]",
			})
			return
		}
		if _, exists := seenGrants[g]; exists {
			// airlockvet:allow-writejson reason: RFC 7591 dynamic client registration errors use the standardized JSON shape
			writeJSON(w, http.StatusBadRequest, dcrError{Error: "invalid_client_metadata", ErrorDescription: "grant_types must be unique"})
			return
		}
		seenGrants[g] = struct{}{}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if len(req.ResponseTypes) != 1 {
		// airlockvet:allow-writejson reason: RFC 7591 dynamic client registration errors use the standardized JSON shape
		writeJSON(w, http.StatusBadRequest, dcrError{Error: "invalid_client_metadata", ErrorDescription: "exactly one response_type is required"})
		return
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
	if !containsStr(req.GrantTypes, "authorization_code") {
		// airlockvet:allow-writejson reason: RFC 7591 dynamic client registration errors use the standardized JSON shape
		writeJSON(w, http.StatusBadRequest, dcrError{Error: "invalid_client_metadata", ErrorDescription: "response_type=code requires grant_type=authorization_code"})
		return
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

	if req.Scope == "" {
		req.Scope = "mcp"
	}
	if req.Scope != "mcp" {
		// airlockvet:allow-writejson reason: RFC 7591 dynamic client registration errors use the standardized JSON shape
		writeJSON(w, http.StatusBadRequest, dcrError{Error: "invalid_client_metadata", ErrorDescription: "scope must be 'mcp'"})
		return
	}

	clientID, err := newClientID()
	if err != nil {
		h.logger.Error("oauth register: client_id gen", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, dcrError{Error: "server_error"})
		return
	}

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
	for _, name := range []string{"client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "resource"} {
		if len(q[name]) != 1 {
			renderOAuthError(w, "invalid_request", name+" must appear exactly once")
			return
		}
	}
	for _, name := range []string{"scope", "state"} {
		if len(q[name]) > 1 {
			renderOAuthError(w, "invalid_request", name+" must not be repeated")
			return
		}
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	resource := q.Get("resource")
	scope := q.Get("scope")
	state := q.Get("state")
	if len(clientID) > 128 || len(redirectURI) > 2048 || len(resource) > 2048 || len(state) > 1024 || len(scope) > 128 {
		renderOAuthError(w, "invalid_request", "authorization parameter too long")
		return
	}

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
	if !validPKCEChallenge(codeChallenge) {
		renderOAuthError(w, "invalid_request", "code_challenge must be a 43-character base64url SHA-256 value")
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
	if !oauthClientAllows(client, "authorization_code", "code", "mcp") {
		renderOAuthError(w, "unauthorized_client", "client metadata does not permit this request")
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

	// Scope is optional and defaults to the client's registered scope.
	if scope == "" {
		scope = client.Scope
	}
	if scope != "mcp" {
		redirectWithError(w, r, redirectURI, state, "invalid_scope", "only scope 'mcp' is supported")
		return
	}

	// Step 6: read the session cookie. If absent / invalid, redirect
	// to /login with a redirect parameter back here. The SPA login
	// flow already supports ?redirect= to arbitrary in-app paths.
	claims, err := h.userFromSessionCookie(r)
	if err != nil {
		// Return through /authorize after login so the server validates and
		// binds the consent request to the newly authenticated user.
		authorizeURL := h.publicURL + "/oauth/authorize?" + r.URL.RawQuery
		loginURL := h.publicURL + "/login?redirect=" + url.QueryEscape(authorizeURL)
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		renderOAuthError(w, "access_denied", "invalid user session")
		return
	}
	if !h.userEntitledToAgent(r.Context(), userID, auth.Role(claims.TenantRole), agentID) {
		redirectWithError(w, r, redirectURI, state, "access_denied", "user is not entitled to this agent")
		return
	}

	// Step 7: serialize this grant's lifecycle across replicas. The same lock is
	// held by consent decisions and revocation, so a transaction cannot appear
	// immediately after revocation has invalidated pending consent screens.
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		redirectWithError(w, r, redirectURI, state, "server_error", "")
		return
	}
	defer tx.Rollback(r.Context())
	txq := dbq.New(tx)
	lockParams := dbq.LockOAuthGrantLifecycleParams{
		UserID:   userID.String(),
		ClientID: clientID,
		AgentID:  agentID.String(),
	}
	// airlockvet:allow-dbq reason: OAuth grant lifecycle serialization is keyed by the authenticated user and validated client/agent
	if err := txq.LockOAuthGrantLifecycle(r.Context(), lockParams); err != nil {
		h.logger.Error("oauth authorize: lock grant lifecycle", zap.Error(err))
		redirectWithError(w, r, redirectURI, state, "server_error", "")
		return
	}

	// Skip consent if the serialized grant check finds an active grant.
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	_, gErr := txq.GetActiveGrant(r.Context(), dbq.GetActiveGrantParams{
		UserID: toPgUUID(userID), ClientID: clientID, AgentID: toPgUUID(agentID),
	})
	if gErr == nil {
		code, mErr := h.mintAuthzCodeWithQueries(r.Context(), txq, userID, clientID, agentID, redirectURI, codeChallenge, "mcp", canonResource)
		if mErr != nil {
			h.logger.Error("oauth authorize: mint code", zap.Error(mErr))
			redirectWithError(w, r, redirectURI, state, "server_error", "")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			h.logger.Error("oauth authorize: commit code", zap.Error(err))
			redirectWithError(w, r, redirectURI, state, "server_error", "")
			return
		}
		bounceWithCode(w, r, redirectURI, code, state)
		return
	}
	if !errors.Is(gErr, pgx.ErrNoRows) {
		h.logger.Error("oauth authorize: check grant", zap.Error(gErr))
		redirectWithError(w, r, redirectURI, state, "server_error", "")
		return
	}

	// Bind every security-sensitive parameter to this user. The SPA may
	// display reflected values, but Consent accepts them only with this MAC and
	// the matching single-use database transaction.
	expiresAt := time.Now().Add(10 * time.Minute)
	bound := consentBinding{
		TransactionID: uuid.NewString(), UserID: userID.String(), ClientID: clientID, RedirectURI: redirectURI,
		State: state, CodeChallenge: codeChallenge, Scope: scope,
		Resource: resource, ExpiresAt: expiresAt.Unix(),
	}
	consentToken, err := h.signConsentBinding(bound)
	if err != nil {
		h.logger.Error("oauth authorize: bind consent", zap.Error(err))
		redirectWithError(w, r, redirectURI, state, "server_error", "")
		return
	}
	transactionID, err := uuid.Parse(bound.TransactionID)
	if err != nil {
		panic("api: generated invalid OAuth consent transaction ID")
	}
	// airlockvet:allow-dbq reason: OAuth 2.0 consent transaction is bound to the authenticated user and validated client/agent
	if err := txq.CreateOAuthConsentTransaction(r.Context(), dbq.CreateOAuthConsentTransactionParams{
		TransactionID: toPgUUID(transactionID),
		BindingHash:   hashToken(consentToken),
		UserID:        toPgUUID(userID),
		ClientID:      clientID,
		AgentID:       toPgUUID(agentID),
		ExpiresAt:     pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}); err != nil {
		h.logger.Error("oauth authorize: persist consent", zap.Error(err))
		redirectWithError(w, r, redirectURI, state, "server_error", "")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("oauth authorize: commit consent", zap.Error(err))
		redirectWithError(w, r, redirectURI, state, "server_error", "")
		return
	}
	consentURL := h.publicURL + "/oauth/consent?" + r.URL.RawQuery
	consentURL = buildRedirectURL(consentURL, map[string]string{"consent_token": consentToken})
	http.Redirect(w, r, consentURL, http.StatusFound)
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
	ConsentToken        string `json:"consent_token"`
}

type consentBinding struct {
	TransactionID string `json:"tid"`
	UserID        string `json:"uid"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state"`
	CodeChallenge string `json:"code_challenge"`
	Scope         string `json:"scope"`
	Resource      string `json:"resource"`
	ExpiresAt     int64  `json:"exp"`
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

	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	defer r.Body.Close()
	var req consentRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	bound, err := h.verifyConsentBinding(req.ConsentToken)
	if err != nil || bound.UserID != userID.String() ||
		bound.ClientID != req.ClientID || bound.RedirectURI != req.RedirectURI ||
		bound.State != req.State || bound.CodeChallenge != req.CodeChallenge ||
		bound.Scope != req.Scope || bound.Resource != req.Resource {
		// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
		writeJSONError(w, http.StatusBadRequest, "invalid or expired consent request")
		return
	}
	transactionID, err := uuid.Parse(bound.TransactionID)
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
		writeJSONError(w, http.StatusBadRequest, "invalid or expired consent request")
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
	if !oauthClientAllows(client, "authorization_code", "code", req.Scope) {
		// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
		writeJSONError(w, http.StatusBadRequest, "client metadata does not permit this request")
		return
	}
	if !containsStr(client.RedirectUris, req.RedirectURI) {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, "redirect_uri mismatch")
		return
	}
	if req.CodeChallengeMethod != "S256" || !validPKCEChallenge(req.CodeChallenge) {
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
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || !h.userEntitledToAgent(r.Context(), userID, auth.Role(claims.TenantRole), agentID) {
		// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
		writeJSONError(w, http.StatusForbidden, "user is not entitled to this agent")
		return
	}

	if req.Decision != "approve" && req.Decision != "deny" {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusBadRequest, "decision must be 'approve' or 'deny'")
		return
	}

	// Consume the consent transaction in the same transaction as the decision's
	// effects. Concurrent approve/deny requests have exactly one winner.
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	defer tx.Rollback(r.Context())
	txq := dbq.New(tx)
	// airlockvet:allow-dbq reason: OAuth grant lifecycle serialization is keyed by the authenticated user and validated client/agent
	if err := txq.LockOAuthGrantLifecycle(r.Context(), dbq.LockOAuthGrantLifecycleParams{
		UserID: userID.String(), ClientID: req.ClientID, AgentID: agentID.String(),
	}); err != nil {
		h.logger.Error("oauth consent: lock grant lifecycle", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	// airlockvet:allow-dbq reason: OAuth 2.0 consent transaction is bound to the authenticated user and validated client/agent
	if _, err := txq.ConsumeOAuthConsentTransaction(r.Context(), dbq.ConsumeOAuthConsentTransactionParams{
		TransactionID: toPgUUID(transactionID),
		BindingHash:   hashToken(req.ConsentToken),
		UserID:        toPgUUID(userID),
		ClientID:      req.ClientID,
		AgentID:       toPgUUID(agentID),
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
			writeJSONError(w, http.StatusBadRequest, "invalid or expired consent request")
		} else {
			h.logger.Error("oauth consent: consume transaction", zap.Error(err))
			// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
			writeJSONError(w, http.StatusInternalServerError, "server error")
		}
		return
	}
	if req.Decision == "deny" {
		if err := tx.Commit(r.Context()); err != nil {
			h.logger.Error("oauth consent: commit denial", zap.Error(err))
			// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
			writeJSONError(w, http.StatusInternalServerError, "server error")
			return
		}
		bounceURL := buildRedirectURL(req.RedirectURI, map[string]string{
			"error":             "access_denied",
			"error_description": "user denied consent",
			"state":             req.State,
		})
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusOK, consentResponse{RedirectTo: bounceURL})
		return
	}

	// Mint a code and grant so subsequent /authorize requests skip consent.
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	if err := txq.UpsertGrant(r.Context(), dbq.UpsertGrantParams{
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
	code, err := h.mintAuthzCodeWithQueries(r.Context(), txq, userID, req.ClientID, agentID, req.RedirectURI, req.CodeChallenge, "mcp", canonResource)
	if err != nil {
		h.logger.Error("oauth consent: mint code", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSONError(w, http.StatusInternalServerError, "server error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("oauth consent: commit", zap.Error(err))
		// airlockvet:allow-writejson reason: OAuth consent uses JSON between the authenticated SPA and protocol endpoint
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
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_request"})
		return
	}
	if len(r.PostForm["grant_type"]) != 1 {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_request"})
		return
	}
	for _, name := range []string{"code", "client_id", "redirect_uri", "code_verifier", "resource", "refresh_token"} {
		if len(r.PostForm[name]) > 1 {
			// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
			writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_request"})
			return
		}
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

	if code == "" || len(code) > 128 || clientID == "" || len(clientID) > 128 ||
		redirectURI == "" || len(redirectURI) > 2048 || !validPKCEVerifier(codeVerifier) || len(resource) > 2048 {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_request"})
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}
	defer tx.Rollback(r.Context())
	q := dbq.New(tx)
	// airlockvet:allow-dbq reason: OAuth code exchange validates registered client metadata inside the single-use code transaction
	client, err := q.GetOAuthClient(r.Context(), clientID)
	if err != nil || !oauthClientAllows(client, "authorization_code", "code", "mcp") {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "unauthorized_client"})
		return
	}
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
	if resource != "" {
		_, canonicalResource, err := h.canonicalizeResource(r.Context(), resource)
		if err != nil || canonicalResource != row.Resource {
			// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
			writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "resource mismatch"})
			return
		}
	}
	if !verifyPKCE(codeVerifier, row.CodeChallenge) {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "PKCE verifier failed"})
		return
	}

	// Mint access JWT + opaque refresh.
	userID := uuid.UUID(row.UserID.Bytes)
	// airlockvet:allow-dbq reason: OAuth code exchange revalidates the code owner's live account inside the transaction
	user, err := q.GetUserByID(r.Context(), row.UserID)
	if err != nil || !h.userEntitledToAgentWithQueries(r.Context(), q, userID, auth.Role(user.TenantRole), uuid.UUID(row.AgentID.Bytes)) {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "user is no longer entitled to this agent"})
		return
	}
	// airlockvet:allow-dbq reason: OAuth code exchange revalidates the exact user/client/agent grant inside the transaction
	if _, err := q.GetActiveGrant(r.Context(), dbq.GetActiveGrantParams{UserID: row.UserID, ClientID: clientID, AgentID: row.AgentID}); err != nil {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "grant revoked or expired"})
		return
	}

	accessToken, err := auth.IssueOAuthAccessToken(h.jwtSecret, userID, user.Email, user.TenantRole, clientID, row.Scope, row.Resource, user.AuthEpoch)
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
	if err := q.TouchOAuthClient(r.Context(), clientID); err != nil {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("oauth token: commit code exchange", zap.Error(err))
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}

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

	if len(refresh) > 256 || len(clientID) > 128 {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_request"})
		return
	}
	hash := hashToken(refresh)
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}
	defer tx.Rollback(r.Context())
	q := dbq.New(tx)
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	row, err := q.GetRefreshTokenByHashForUpdate(r.Context(), hash)
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
	// airlockvet:allow-dbq reason: OAuth refresh validates registered client metadata inside the token-family transaction
	client, err := q.GetOAuthClient(r.Context(), clientID)
	if err != nil || !oauthClientAllows(client, "refresh_token", "", row.Scope) {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "unauthorized_client"})
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
		if _, err := q.RevokeRefreshFamily(r.Context(), row.FamilyID); err != nil {
			// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
			writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
			writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
			return
		}
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
	userID := uuid.UUID(row.UserID.Bytes)
	// airlockvet:allow-dbq reason: OAuth refresh revalidates the token owner's live account inside the transaction
	user, err := q.GetUserByID(r.Context(), row.UserID)
	if err != nil || !h.userEntitledToAgentWithQueries(r.Context(), q, userID, auth.Role(user.TenantRole), uuid.UUID(row.AgentID.Bytes)) {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusBadRequest, tokenError{Error: "invalid_grant", ErrorDescription: "user is no longer entitled to this agent"})
		return
	}

	newRaw, err := newRefreshToken()
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}
	newHash := hashToken(newRaw)
	audience := fmt.Sprintf("%s/api/agent/%s/mcp", h.publicURL, uuid.UUID(row.AgentID.Bytes).String())
	access, err := auth.IssueOAuthAccessToken(h.jwtSecret, userID, user.Email, user.TenantRole, clientID, row.Scope, audience, user.AuthEpoch)
	if err != nil {
		h.logger.Error("oauth token refresh: issue access", zap.Error(err))
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}
	// airlockvet:allow-dbq reason: OAuth 2.0 / RFC 6749 endpoint — wire is JSON by spec; client_id + grant flow drives authz, not user Principal
	if _, err := q.MarkRefreshConsumed(r.Context(), hash); err != nil {
		h.logger.Error("oauth token refresh: mark consumed", zap.Error(err))
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}
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
	// airlockvet:allow-dbq reason: OAuth refresh records use of the validated client inside the token-family transaction
	if err := q.TouchOAuthClient(r.Context(), clientID); err != nil {
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
		writeJSON(w, http.StatusInternalServerError, tokenError{Error: "server_error"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("oauth token refresh: commit", zap.Error(err))
		// airlockvet:allow-writejson reason: RFC 6749 token endpoint responses use standardized JSON errors
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
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		// airlockvet:allow-writejson reason: OAuth grant management is a JSON SPA endpoint
		writeJSONError(w, http.StatusInternalServerError, "revoke")
		return
	}
	defer tx.Rollback(r.Context())
	q := dbq.New(tx)
	// airlockvet:allow-dbq reason: OAuth grant lifecycle serialization is keyed by the authenticated user and validated client/agent
	if err := q.LockOAuthGrantLifecycle(r.Context(), dbq.LockOAuthGrantLifecycleParams{
		UserID: userID.String(), ClientID: clientID, AgentID: agentID.String(),
	}); err != nil {
		// airlockvet:allow-writejson reason: OAuth grant management is a JSON SPA endpoint
		writeJSONError(w, http.StatusInternalServerError, "revoke")
		return
	}
	// Invalidate consent screens issued before this revocation. Consent handling
	// and revocation hold the same lifecycle lock across all row mutations.
	// airlockvet:allow-dbq reason: grant revocation invalidates pending OAuth consent transactions for the same user/client/agent
	if _, err := q.DeleteOAuthConsentTransactionsForGrant(r.Context(), dbq.DeleteOAuthConsentTransactionsForGrantParams{
		UserID:   toPgUUID(userID),
		ClientID: clientID,
		AgentID:  toPgUUID(agentID),
	}); err != nil {
		// airlockvet:allow-writejson reason: OAuth grant management is a JSON SPA endpoint
		writeJSONError(w, http.StatusInternalServerError, "revoke")
		return
	}
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
	if _, err := q.RevokeRefreshForGrant(r.Context(), dbq.RevokeRefreshForGrantParams{
		UserID:   toPgUUID(userID),
		ClientID: clientID,
		AgentID:  toPgUUID(agentID),
	}); err != nil {
		// airlockvet:allow-writejson reason: OAuth grant management is a JSON SPA endpoint
		writeJSONError(w, http.StatusInternalServerError, "revoke")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		// airlockvet:allow-writejson reason: OAuth grant management is a JSON SPA endpoint
		writeJSONError(w, http.StatusInternalServerError, "revoke")
		return
	}
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
	if identifier == "" || strings.ContainsAny(identifier, "/?#\\") || len(identifier) > 128 {
		return uuid.Nil, "", fmt.Errorf("missing agent identifier in resource")
	}
	q := dbq.New(h.db.Pool())
	ag, err := lookupAgentByIdentifier(ctx, q, identifier)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("unknown agent")
	}
	if !ag.McpEnabled {
		return uuid.Nil, "", fmt.Errorf("agent MCP endpoint is disabled")
	}
	agentID := uuid.UUID(ag.ID.Bytes)
	canonical := fmt.Sprintf("%s/api/agent/%s/mcp", h.publicURL, agentID.String())
	return agentID, canonical, nil
}

func (h *oauthServerHandler) mintAuthzCode(ctx context.Context, userID uuid.UUID, clientID string, agentID uuid.UUID, redirectURI, codeChallenge, scope, resource string) (string, error) {
	return h.mintAuthzCodeWithQueries(ctx, dbq.New(h.db.Pool()), userID, clientID, agentID, redirectURI, codeChallenge, scope, resource)
}

func (h *oauthServerHandler) mintAuthzCodeWithQueries(ctx context.Context, q *dbq.Queries, userID uuid.UUID, clientID string, agentID uuid.UUID, redirectURI, codeChallenge, scope, resource string) (string, error) {
	code, err := newAuthzCode()
	if err != nil {
		return "", err
	}
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

func (h *oauthServerHandler) userFromSessionCookie(r *http.Request) (*auth.Claims, error) {
	c, err := r.Cookie(accessCookieName)
	if err != nil {
		return nil, err
	}
	claims, err := auth.ValidateUserAccessToken(h.jwtSecret, c.Value)
	if err != nil {
		return nil, err
	}
	claims, err = auth.ResolveLiveUserClaims(r.Context(), dbq.New(h.db.Pool()), claims, true)
	if err != nil || claims.MustChangePassword {
		return nil, errors.New("password change required")
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, err
	}
	return claims, nil
}

func (h *oauthServerHandler) userEntitledToAgent(ctx context.Context, userID uuid.UUID, role auth.Role, agentID uuid.UUID) bool {
	return h.userEntitledToAgentWithQueries(ctx, dbq.New(h.db.Pool()), userID, role, agentID)
}

func (h *oauthServerHandler) userEntitledToAgentWithQueries(ctx context.Context, q *dbq.Queries, userID uuid.UUID, role auth.Role, agentID uuid.UUID) bool {
	// airlockvet:allow-dbq reason: OAuth entitlement checks read the target agent's live MCP availability before policy resolution
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil || !agent.McpEnabled {
		return false
	}
	_, granted := authz.UserPrincipal(userID, role).EffectiveAgentAccessGranted(ctx, q, agentID)
	return granted
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
	if !validPKCEVerifier(verifier) || !validPKCEChallenge(challenge) {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func validPKCEVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-._~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

func validPKCEChallenge(v string) bool {
	if len(v) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == sha256.Size && base64.RawURLEncoding.EncodeToString(b) == v
}

func isValidRedirectURI(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\t") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.User != nil || u.Host == "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Hostname() != ""
	case "http":
		addr, err := netip.ParseAddr(u.Hostname())
		return err == nil && addr.IsLoopback()
	default:
		return false
	}
}

func oauthClientAllows(client dbq.OauthClient, grantType, responseType, scope string) bool {
	if client.TokenEndpointAuthMethod != "none" || client.Scope != "mcp" || scope != "mcp" {
		return false
	}
	if grantType != "" && !containsStr(client.GrantTypes, grantType) {
		return false
	}
	return responseType == "" || containsStr(client.ResponseTypes, responseType)
}

func (h *oauthServerHandler) signConsentBinding(binding consentBinding) (string, error) {
	payload, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(h.jwtSecret))
	mac.Write([]byte("oauth-consent-v1:" + encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (h *oauthServerHandler) verifyConsentBinding(token string) (consentBinding, error) {
	var binding consentBinding
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(token) > 16<<10 {
		return binding, fmt.Errorf("invalid consent token")
	}
	mac := hmac.New(sha256.New, []byte(h.jwtSecret))
	mac.Write([]byte("oauth-consent-v1:" + parts[0]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return binding, fmt.Errorf("invalid consent token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(payload, &binding) != nil || binding.ExpiresAt < time.Now().Unix() {
		return consentBinding{}, fmt.Errorf("invalid or expired consent token")
	}
	return binding, nil
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
	return r.Header.Get("Origin") == configuredOrigin(publicURL)
}
