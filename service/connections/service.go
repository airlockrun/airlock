// Package connections owns per-agent credential management:
// connections (API key / OAuth), MCP servers, env vars, and the
// aggregate setup-status signal.
//
// Authorization uses the standard agent-admin gate (agent_members.role
// = 'admin'), the same ladder used by members, siblings, and agent
// configuration ops.
package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// ToolInfo is one MCP tool returned from discovery (the api-package
// mcpToolInfo, mirrored here so the service doesn't import api).
type ToolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// DiscoveryFunc runs MCP tools/list and returns the discovered tool
// schemas plus the server-level instructions. Injected from the api
// package so the service doesn't depend on the goai/mcp client.
type DiscoveryFunc func(ctx context.Context, serverURL string, authInjection []byte, creds string) ([]ToolInfo, string, error)

// AuthDiscoveryFunc runs RFC 9728/8414 discovery on an MCP server URL.
type AuthDiscoveryFunc func(ctx context.Context, serverURL string) (*oauth.DiscoveryResult, error)

// AuthInjector adds credentials to an outbound HTTP request given the
// stored auth_injection config and decrypted creds.
type AuthInjector func(req *http.Request, authInjection []byte, creds string)

// RefreshAgentFunc pushes a /refresh into a running agent container so
// it picks up new MCP tool schemas without a container restart.
type RefreshAgentFunc func(ctx context.Context, agentID uuid.UUID) error

type Service struct {
	db           *db.DB
	encryptor    secrets.Store
	oauthClient  *oauth.Client
	publicURL    string
	refresh      RefreshAgentFunc
	logger       *zap.Logger
	discover     DiscoveryFunc
	discoverAuth AuthDiscoveryFunc
	injectAuth   AuthInjector
	mcpHTTP      *http.Client
}

func New(
	d *db.DB,
	enc secrets.Store,
	oc *oauth.Client,
	publicURL string,
	refresh RefreshAgentFunc,
	logger *zap.Logger,
	discover DiscoveryFunc,
	discoverAuth AuthDiscoveryFunc,
	injectAuth AuthInjector,
	mcpHTTP *http.Client,
) *Service {
	if d == nil {
		panic("connections: db is required")
	}
	if enc == nil {
		panic("connections: encryptor is required")
	}
	if oc == nil {
		panic("connections: oauth client is required")
	}
	if refresh == nil {
		panic("connections: refresh func is required")
	}
	if logger == nil {
		panic("connections: logger is required")
	}
	if discover == nil {
		panic("connections: discover func is required")
	}
	if discoverAuth == nil {
		panic("connections: discoverAuth func is required")
	}
	if injectAuth == nil {
		panic("connections: injectAuth func is required")
	}
	if mcpHTTP == nil {
		panic("connections: mcpHTTP client is required")
	}
	return &Service{
		db: d, encryptor: enc, oauthClient: oc, publicURL: publicURL,
		refresh: refresh, logger: logger,
		discover: discover, discoverAuth: discoverAuth, injectAuth: injectAuth,
		mcpHTTP: mcpHTTP,
	}
}

func toPg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// --- types ---

// Status is the common CredentialStatus response shape.
type Status struct {
	Slug           string
	Name           string
	AuthMode       string
	Authorized     bool
	TokenExpiresAt time.Time // zero when unset
}

// Connection is one row from ListConnections.
type Connection struct {
	ID                uuid.UUID
	Slug              string
	Name              string
	Description       string
	AuthMode          string
	Authorized        bool
	HasOAuthApp       bool
	HasRefreshToken   bool
	SetupInstructions string
	TokenExpiresAt    pgtype.Timestamptz
}

// ConnectionsList wraps List + the OAuth callback URL the UI needs to
// show the operator.
type ConnectionsList struct {
	Connections      []Connection
	OAuthCallbackURL string
}

// TestResult is the body of TestCredential.
type TestResult struct {
	Success    bool
	StatusCode int32
	Message    string
}

// MCPServer is one row from ListMCPServers.
type MCPServer struct {
	ID             uuid.UUID
	Slug           string
	Name           string
	URL            string
	AuthMode       string
	Authorized     bool
	HasOAuthApp    bool
	ToolCount      int
	TokenExpiresAt *time.Time
	LastSyncedAt   *time.Time
}

// MCPStatus is the response for MCP status/set endpoints.
type MCPStatus struct {
	Slug       string
	Name       string
	AuthMode   string
	Authorized bool
}

// EnvVar is one row from ListEnvVars.
type EnvVar struct {
	Slug         string
	Description  string
	IsSecret     bool
	Configured   bool
	Pattern      string
	DefaultValue string
	Value        string // populated only when !IsSecret and Configured
	UpdatedAt    time.Time
}

// SetupCounts is the body of SetupStatus.
type SetupCounts struct {
	Connections int32
	MCPServers  int32
	EnvVars     int32
}

// --- connections ---

// ensureBoundConnection makes sure a connection resource exists for the agent's
// declared need, creating it — owned by the configuring principal — and binding
// it on first credential configuration. Returns ErrNotFound if the agent never
// declared the slug as a need.
func (s *Service) ensureBoundConnection(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID, slug string) error {
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: toPg(agentID), Type: "connection", Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return service.Detail(service.ErrNotFound, "connection not declared by the agent")
		}
		return err
	}
	if need.BoundConnectionID.Valid {
		return nil
	}
	var spec struct {
		Name              string          `json:"name"`
		AuthMode          string          `json:"auth_mode"`
		AuthURL           string          `json:"auth_url"`
		TokenURL          string          `json:"token_url"`
		BaseURL           string          `json:"base_url"`
		Scopes            string          `json:"scopes"`
		AuthInjection     json.RawMessage `json:"auth_injection"`
		AuthParams        json.RawMessage `json:"auth_params"`
		Headers           json.RawMessage `json:"headers"`
		LLMHint           string          `json:"llm_hint"`
		Access            string          `json:"access"`
		SetupInstructions string          `json:"setup_instructions"`
	}
	_ = json.Unmarshal(need.Spec, &spec)
	jsonOr := func(b json.RawMessage) []byte {
		if len(b) == 0 {
			return []byte("{}")
		}
		return b
	}
	conn, err := q.UpsertConnection(ctx, dbq.UpsertConnectionParams{
		AgentID: toPg(agentID), Slug: slug, Name: spec.Name, Description: need.Description, LlmHint: spec.LLMHint,
		AuthMode: spec.AuthMode, AuthUrl: spec.AuthURL, TokenUrl: spec.TokenURL, BaseUrl: spec.BaseURL,
		Scopes: spec.Scopes, AuthInjection: jsonOr(spec.AuthInjection), SetupInstructions: spec.SetupInstructions,
		Config: []byte("{}"), AuthParams: jsonOr(spec.AuthParams), Headers: jsonOr(spec.Headers), Access: spec.Access,
	})
	if err != nil {
		return err
	}
	if p.UserID != uuid.Nil {
		if err := q.UpdateConnectionOwnerByID(ctx, dbq.UpdateConnectionOwnerByIDParams{ID: conn.ID, OwnerPrincipalID: toPg(p.UserID)}); err != nil {
			return err
		}
	}
	return q.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{AgentID: toPg(agentID), Slug: slug, ResourceID: conn.ID})
}

// SetOAuthApp persists encrypted client_id/client_secret for a connection.
func (s *Service) SetOAuthApp(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, clientID, clientSecret string) (Status, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return Status{}, err
	}
	if err := s.ensureBoundConnection(ctx, q, p, agentID, slug); err != nil {
		return Status{}, err
	}
	conn, err := q.GetConnectionForOAuth(ctx, dbq.GetConnectionForOAuthParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Status{}, service.Detail(service.ErrNotFound, "connection not found")
		}
		s.logger.Error("get connection failed", zap.Error(err))
		return Status{}, err
	}
	if conn.AuthMode != "oauth" {
		return Status{}, service.Detail(service.ErrInvalidInput, "connection is not OAuth — use API key endpoint")
	}
	connRef := "connection/" + uuid.UUID(conn.ID.Bytes).String()
	encClientID, err := s.encryptor.Put(ctx, connRef+"/client_id", clientID)
	if err != nil {
		s.logger.Error("encrypt client_id failed", zap.Error(err))
		return Status{}, err
	}
	encClientSecret, err := s.encryptor.Put(ctx, connRef+"/client_secret", clientSecret)
	if err != nil {
		s.logger.Error("encrypt client_secret failed", zap.Error(err))
		return Status{}, err
	}
	if err := q.UpdateConnectionOAuthApp(ctx, dbq.UpdateConnectionOAuthAppParams{
		AgentID: toPg(agentID), Slug: slug, ClientID: encClientID, ClientSecret: encClientSecret,
	}); err != nil {
		s.logger.Error("update oauth app failed", zap.Error(err))
		return Status{}, err
	}
	return Status{Slug: slug, Name: conn.Name, AuthMode: "oauth", Authorized: false}, nil
}

// OAuthStart generates a PKCE pair + state row and returns the
// authorize URL the user should redirect to.
func (s *Service) OAuthStart(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, redirectURI string) (string, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return "", err
	}
	conn, err := q.GetConnectionForOAuth(ctx, dbq.GetConnectionForOAuthParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", service.Detail(service.ErrNotFound, "connection not found")
		}
		s.logger.Error("get connection failed", zap.Error(err))
		return "", err
	}
	if conn.AuthMode != "oauth" {
		return "", service.Detail(service.ErrInvalidInput, "connection is not OAuth")
	}
	if conn.ClientID == "" {
		return "", service.Detail(service.ErrInvalidInput, "OAuth app not configured. Set client_id and client_secret first.")
	}
	connRef := "connection/" + uuid.UUID(conn.ID.Bytes).String()
	clientID, err := s.encryptor.Get(ctx, connRef+"/client_id", conn.ClientID)
	if err != nil {
		s.logger.Error("decrypt client_id failed", zap.Error(err))
		return "", err
	}
	verifier, challenge, err := oauth.GeneratePKCE()
	if err != nil {
		return "", err
	}
	state, err := oauth.GenerateState()
	if err != nil {
		return "", err
	}
	encVerifier, err := s.encryptor.Put(ctx, "oauth_state/"+state+"/code_verifier", verifier)
	if err != nil {
		return "", err
	}
	if err := q.CreateOAuthState(ctx, dbq.CreateOAuthStateParams{
		State: state, AgentID: toPg(agentID), Slug: slug,
		CodeVerifier: encVerifier, RedirectUri: redirectURI,
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(10 * time.Minute), Valid: true},
		SourceType: "connection",
	}); err != nil {
		return "", err
	}
	authParams := map[string]string{"access_type": "offline", "prompt": "consent"}
	if len(conn.AuthParams) > 0 {
		var override map[string]string
		if jsonErr := json.Unmarshal(conn.AuthParams, &override); jsonErr == nil {
			for k, v := range override {
				if v == "" {
					delete(authParams, k)
					continue
				}
				authParams[k] = v
			}
		}
	}
	callbackURL := s.publicURL + "/api/v1/credentials/oauth/callback"
	return s.oauthClient.BuildAuthURL(conn.AuthUrl, clientID, callbackURL, state, challenge, conn.Scopes, authParams)
}

// OAuthCallbackResult tells the caller where to redirect the browser
// after the OAuth dance completes (or fails).
type OAuthCallbackResult struct {
	RedirectURL string
}

// ErrOAuthMissingParams is returned when code/state aren't both present.
var ErrOAuthMissingParams = service.Detail(service.ErrInvalidInput, "missing code or state parameter")

// ErrOAuthInvalidState is returned for an unknown or expired state row.
var ErrOAuthInvalidState = service.Detail(service.ErrInvalidInput, "invalid or expired state")

// OAuthCallback handles the provider's redirect after consent. Returns
// the URL to redirect the browser to (either the original redirect_uri
// success page, or that URL with error params if the exchange failed).
func (s *Service) OAuthCallback(ctx context.Context, code, state string) (OAuthCallbackResult, error) {
	if code == "" || state == "" {
		return OAuthCallbackResult{}, ErrOAuthMissingParams
	}
	q := dbq.New(s.db.Pool())
	oauthState, err := q.GetOAuthState(ctx, state)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OAuthCallbackResult{}, ErrOAuthInvalidState
		}
		s.logger.Error("get oauth state failed", zap.Error(err))
		return OAuthCallbackResult{}, err
	}
	agentID := uuid.UUID(oauthState.AgentID.Bytes)
	verifier, err := s.encryptor.Get(ctx, "oauth_state/"+state+"/code_verifier", oauthState.CodeVerifier)
	if err != nil {
		s.logger.Error("decrypt verifier failed", zap.Error(err))
		return OAuthCallbackResult{}, err
	}
	var tokenURL, clientIDEnc, clientSecretEnc, sourceRef string
	if oauthState.SourceType == "mcp" {
		srv, err := q.GetMCPServerForOAuth(ctx, dbq.GetMCPServerForOAuthParams{AgentID: oauthState.AgentID, Slug: oauthState.Slug})
		if err != nil {
			s.logger.Error("get MCP server for callback failed", zap.Error(err))
			return OAuthCallbackResult{}, err
		}
		tokenURL = srv.TokenUrl
		clientIDEnc = srv.ClientID
		clientSecretEnc = srv.ClientSecret
		sourceRef = "mcp/" + uuid.UUID(srv.ID.Bytes).String()
	} else {
		conn, err := q.GetConnectionForOAuth(ctx, dbq.GetConnectionForOAuthParams{AgentID: oauthState.AgentID, Slug: oauthState.Slug})
		if err != nil {
			s.logger.Error("get connection for callback failed", zap.Error(err))
			return OAuthCallbackResult{}, err
		}
		tokenURL = conn.TokenUrl
		clientIDEnc = conn.ClientID
		clientSecretEnc = conn.ClientSecret
		sourceRef = "connection/" + uuid.UUID(conn.ID.Bytes).String()
	}
	clientID, err := s.encryptor.Get(ctx, sourceRef+"/client_id", clientIDEnc)
	if err != nil {
		s.logger.Error("decrypt client_id failed", zap.Error(err))
		return OAuthCallbackResult{}, err
	}
	clientSecret, err := s.encryptor.Get(ctx, sourceRef+"/client_secret", clientSecretEnc)
	if err != nil {
		s.logger.Error("decrypt client_secret failed", zap.Error(err))
		return OAuthCallbackResult{}, err
	}
	callbackURL := s.publicURL + "/api/v1/credentials/oauth/callback"
	tokenResp, err := s.oauthClient.ExchangeCode(ctx, tokenURL, code, verifier, callbackURL, clientID, clientSecret)
	if err != nil {
		s.logger.Error("token exchange failed", zap.Error(err))
		redir := s.defaultRedirectURI(oauthState.RedirectUri, agentID)
		return OAuthCallbackResult{RedirectURL: redir + "?error=exchange_failed&message=" + err.Error()}, nil
	}
	encAccessToken, err := s.encryptor.Put(ctx, sourceRef+"/access_token", tokenResp.AccessToken)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	var encRefreshToken string
	if tokenResp.RefreshToken != "" {
		encRefreshToken, err = s.encryptor.Put(ctx, sourceRef+"/refresh_token", tokenResp.RefreshToken)
		if err != nil {
			return OAuthCallbackResult{}, err
		}
	}
	var expiresAt pgtype.Timestamptz
	if tokenResp.ExpiresIn > 0 {
		expiresAt = pgtype.Timestamptz{Time: time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second), Valid: true}
	}
	if oauthState.SourceType == "mcp" {
		if err := q.UpdateMCPServerCredentials(ctx, dbq.UpdateMCPServerCredentialsParams{
			AgentID: oauthState.AgentID, Slug: oauthState.Slug,
			AccessTokenRef: encAccessToken, TokenExpiresAt: expiresAt, RefreshToken: encRefreshToken,
		}); err != nil {
			s.logger.Error("store MCP credentials failed", zap.Error(err))
			return OAuthCallbackResult{}, err
		}
		s.refreshMCPAfterAuth(ctx, agentID, oauthState.Slug, tokenResp.AccessToken)
	} else {
		if err := q.UpdateConnectionCredentials(ctx, dbq.UpdateConnectionCredentialsParams{
			AgentID: oauthState.AgentID, Slug: oauthState.Slug,
			AccessTokenRef: encAccessToken, TokenExpiresAt: expiresAt, RefreshToken: encRefreshToken,
		}); err != nil {
			s.logger.Error("store credentials failed", zap.Error(err))
			return OAuthCallbackResult{}, err
		}
	}
	_ = q.DeleteOAuthState(ctx, state)
	return OAuthCallbackResult{RedirectURL: s.defaultRedirectURI(oauthState.RedirectUri, agentID)}, nil
}

// PublicURL exposes the configured public URL for handler URL synthesis.
func (s *Service) PublicURL() string { return s.publicURL }

func (s *Service) defaultRedirectURI(stateRedirect string, agentID uuid.UUID) string {
	if stateRedirect != "" {
		return stateRedirect
	}
	return fmt.Sprintf("%s/agents/%s", s.publicURL, agentID)
}

// refreshMCPAfterAuth re-discovers tools for a freshly-authorized MCP
// server and pushes the running agent container to re-sync. All steps
// are best-effort; the agent will pick up new tools on its next sync.
func (s *Service) refreshMCPAfterAuth(ctx context.Context, agentID uuid.UUID, slug, accessToken string) {
	q := dbq.New(s.db.Pool())
	srv, err := q.GetMCPServerBySlug(ctx, dbq.GetMCPServerBySlugParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		s.logger.Warn("refresh MCP: get server failed", zap.String("slug", slug), zap.Error(err))
		return
	}
	tools, instructions, err := s.discover(ctx, srv.Url, srv.AuthInjection, accessToken)
	if err != nil {
		s.logger.Warn("refresh MCP: discovery failed", zap.String("slug", slug), zap.Error(err))
	} else {
		schemasJSON, _ := json.Marshal(tools)
		if err := q.UpdateMCPServerToolSchemas(ctx, dbq.UpdateMCPServerToolSchemasParams{
			AgentID: toPg(agentID), Slug: slug, ToolSchemas: schemasJSON, ServerInstructions: instructions,
		}); err != nil {
			s.logger.Warn("refresh MCP: persist schemas failed", zap.String("slug", slug), zap.Error(err))
		}
	}
	if err := s.refresh(ctx, agentID); err != nil {
		s.logger.Warn("refresh MCP: agent /refresh failed", zap.String("agent", agentID.String()), zap.Error(err))
	}
}

// SetAPIKey stores an encrypted API key for a non-OAuth connection.
func (s *Service) SetAPIKey(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, apiKey string) (Status, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return Status{}, err
	}
	if err := s.ensureBoundConnection(ctx, q, p, agentID, slug); err != nil {
		return Status{}, err
	}
	conn, err := q.GetConnectionBySlug(ctx, dbq.GetConnectionBySlugParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Status{}, service.Detail(service.ErrNotFound, "connection not found")
		}
		s.logger.Error("get connection failed", zap.Error(err))
		return Status{}, err
	}
	if conn.AuthMode == "oauth" {
		return Status{}, service.Detail(service.ErrInvalidInput, "use OAuth flow for OAuth connections")
	}
	encKey, err := s.encryptor.Put(ctx, "connection/"+uuid.UUID(conn.ID.Bytes).String()+"/access_token", apiKey)
	if err != nil {
		s.logger.Error("encrypt API key failed", zap.Error(err))
		return Status{}, err
	}
	if err := q.UpdateConnectionCredentials(ctx, dbq.UpdateConnectionCredentialsParams{
		AgentID: toPg(agentID), Slug: slug, AccessTokenRef: encKey,
	}); err != nil {
		s.logger.Error("store API key failed", zap.Error(err))
		return Status{}, err
	}
	return Status{Slug: slug, Name: conn.Name, AuthMode: conn.AuthMode, Authorized: true}, nil
}

// ListConnections returns every connection registered against the agent.
func (s *Service) ListConnections(ctx context.Context, p authz.Principal, agentID uuid.UUID) (ConnectionsList, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return ConnectionsList{}, err
	}
	rows, err := q.ListConnectionsWithStatus(ctx, toPg(agentID))
	if err != nil {
		s.logger.Error("list connections failed", zap.Error(err))
		return ConnectionsList{}, err
	}
	out := make([]Connection, len(rows))
	for i, c := range rows {
		out[i] = Connection{
			ID:                uuid.UUID(c.ID.Bytes),
			Slug:              c.Slug,
			Name:              c.Name,
			Description:       c.Description,
			AuthMode:          c.AuthMode,
			Authorized:        c.Authorized,
			HasOAuthApp:       c.HasOauthApp,
			HasRefreshToken:   c.HasRefreshToken,
			SetupInstructions: c.SetupInstructions,
			TokenExpiresAt:    c.TokenExpiresAt,
		}
	}
	return ConnectionsList{
		Connections:      out,
		OAuthCallbackURL: s.publicURL + "/api/v1/credentials/oauth/callback",
	}, nil
}

// CredentialStatus returns the current authorization state of one slug.
func (s *Service) CredentialStatus(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) (Status, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return Status{}, err
	}
	conn, err := q.GetConnectionWithCredentialStatus(ctx, dbq.GetConnectionWithCredentialStatusParams{
		AgentID: toPg(agentID), Slug: slug,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Status{}, service.Detail(service.ErrNotFound, "connection not found")
		}
		s.logger.Error("get credential status failed", zap.Error(err))
		return Status{}, err
	}
	st := Status{Slug: conn.Slug, Name: conn.Name, AuthMode: conn.AuthMode, Authorized: conn.Authorized}
	if conn.TokenExpiresAt.Valid {
		st.TokenExpiresAt = conn.TokenExpiresAt.Time
	}
	return st, nil
}

// RevokeCredential clears the access token + refresh token for a slug.
func (s *Service) RevokeCredential(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return err
	}
	if err := q.ClearConnectionCredentials(ctx, dbq.ClearConnectionCredentialsParams{
		AgentID: toPg(agentID), Slug: slug,
	}); err != nil {
		s.logger.Error("revoke credential failed", zap.Error(err))
		return err
	}
	return nil
}

// TestCredential probes the connection's test_path with stored or
// override credentials. Empty override falls back to stored.
func (s *Service) TestCredential(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, overrideKey string) (TestResult, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return TestResult{}, err
	}
	conn, err := q.GetConnectionBySlug(ctx, dbq.GetConnectionBySlugParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TestResult{}, service.Detail(service.ErrNotFound, "connection not found")
		}
		s.logger.Error("get connection failed", zap.Error(err))
		return TestResult{}, err
	}
	creds := overrideKey
	if creds == "" {
		if conn.AccessTokenRef == "" {
			return TestResult{}, service.Detail(service.ErrInvalidInput, "no credentials configured")
		}
		if conn.TestPath == "" {
			res := TestResult{Success: true, Message: "credentials configured"}
			if conn.AuthMode == "oauth" && conn.TokenExpiresAt.Valid && conn.TokenExpiresAt.Time.Before(time.Now()) {
				res.Success = false
				res.Message = "OAuth token has expired"
			}
			return res, nil
		}
		var derr error
		creds, derr = s.encryptor.Get(ctx, "connection/"+uuid.UUID(conn.ID.Bytes).String()+"/access_token", conn.AccessTokenRef)
		if derr != nil {
			s.logger.Error("decrypt credentials failed", zap.Error(derr))
			return TestResult{}, derr
		}
	}
	if conn.TestPath == "" {
		return TestResult{Success: true, Message: "no test endpoint configured for this connection"}, nil
	}
	testURL := conn.BaseUrl + conn.TestPath
	upstream, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return TestResult{}, service.Detail(service.ErrInvalidInput, "invalid test URL")
	}
	s.injectAuth(upstream, conn.AuthInjection, creds)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(upstream)
	if err != nil {
		return TestResult{Success: false, Message: fmt.Sprintf("request failed: %v", err)}, nil
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
	return TestResult{
		Success:    resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode: int32(resp.StatusCode),
		Message:    msg,
	}, nil
}

// --- MCP servers ---

// ListMCPServers returns all MCP servers + tool counts for the agent.
func (s *Service) ListMCPServers(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]MCPServer, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListMCPServersWithStatus(ctx, toPg(agentID))
	if err != nil {
		s.logger.Error("list MCP servers failed", zap.Error(err))
		return nil, err
	}
	out := make([]MCPServer, len(rows))
	for i, m := range rows {
		ms := MCPServer{
			ID:          uuid.UUID(m.ID.Bytes),
			Slug:        m.Slug,
			Name:        m.Name,
			URL:         m.Url,
			AuthMode:    m.AuthMode,
			Authorized:  m.Authorized,
			HasOAuthApp: m.HasOauthApp,
		}
		var tools []json.RawMessage
		if jerr := json.Unmarshal(m.ToolSchemas, &tools); jerr == nil {
			ms.ToolCount = len(tools)
		}
		if m.TokenExpiresAt.Valid {
			t := m.TokenExpiresAt.Time
			ms.TokenExpiresAt = &t
		}
		if m.LastSyncedAt.Valid {
			t := m.LastSyncedAt.Time
			ms.LastSyncedAt = &t
		}
		out[i] = ms
	}
	return out, nil
}

// MCPCredentialStatus returns the auth state for an MCP server.
func (s *Service) MCPCredentialStatus(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) (MCPStatus, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return MCPStatus{}, err
	}
	srv, err := q.GetMCPServerBySlug(ctx, dbq.GetMCPServerBySlugParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MCPStatus{}, service.Detail(service.ErrNotFound, "MCP server not found")
		}
		s.logger.Error("get MCP server failed", zap.Error(err))
		return MCPStatus{}, err
	}
	return MCPStatus{
		Slug: srv.Slug, Name: srv.Name, AuthMode: srv.AuthMode,
		Authorized: srv.AccessTokenRef != "",
	}, nil
}

// SetMCPToken stores an encrypted token and re-discovers tools.
func (s *Service) SetMCPToken(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, apiKey string) (MCPStatus, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return MCPStatus{}, err
	}
	srv, err := q.GetMCPServerBySlug(ctx, dbq.GetMCPServerBySlugParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MCPStatus{}, service.Detail(service.ErrNotFound, "MCP server not found")
		}
		s.logger.Error("get MCP server failed", zap.Error(err))
		return MCPStatus{}, err
	}
	if srv.AuthMode == "oauth" || srv.AuthMode == "oauth_discovery" {
		return MCPStatus{}, service.Detail(service.ErrInvalidInput, "use OAuth flow for OAuth MCP servers")
	}
	encKey, err := s.encryptor.Put(ctx, "mcp/"+uuid.UUID(srv.ID.Bytes).String()+"/access_token", apiKey)
	if err != nil {
		s.logger.Error("encrypt MCP token failed", zap.Error(err))
		return MCPStatus{}, err
	}
	if err := q.UpdateMCPServerCredentials(ctx, dbq.UpdateMCPServerCredentialsParams{
		AgentID: toPg(agentID), Slug: slug, AccessTokenRef: encKey,
	}); err != nil {
		s.logger.Error("store MCP token failed", zap.Error(err))
		return MCPStatus{}, err
	}
	s.refreshMCPAfterAuth(ctx, agentID, slug, apiKey)
	return MCPStatus{Slug: srv.Slug, Name: srv.Name, AuthMode: srv.AuthMode, Authorized: true}, nil
}

// RevokeMCPCredential clears the access token for an MCP server.
func (s *Service) RevokeMCPCredential(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return err
	}
	if err := q.ClearMCPServerCredentials(ctx, dbq.ClearMCPServerCredentialsParams{AgentID: toPg(agentID), Slug: slug}); err != nil {
		s.logger.Error("revoke MCP credential failed", zap.Error(err))
		return err
	}
	return nil
}

// TestMCPCredential probes the MCP server with tools/list.
func (s *Service) TestMCPCredential(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, overrideKey string) (TestResult, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return TestResult{}, err
	}
	srv, err := q.GetMCPServerBySlug(ctx, dbq.GetMCPServerBySlugParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TestResult{}, service.Detail(service.ErrNotFound, "MCP server not found")
		}
		s.logger.Error("get MCP server failed", zap.Error(err))
		return TestResult{}, err
	}
	creds := overrideKey
	if creds == "" {
		if srv.AccessTokenRef == "" {
			return TestResult{}, service.Detail(service.ErrInvalidInput, "no credentials configured")
		}
		var derr error
		creds, derr = s.encryptor.Get(ctx, "mcp/"+uuid.UUID(srv.ID.Bytes).String()+"/access_token", srv.AccessTokenRef)
		if derr != nil {
			s.logger.Error("decrypt MCP token failed", zap.Error(derr))
			return TestResult{}, derr
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, _, err := s.discover(probeCtx, srv.Url, srv.AuthInjection, creds); err != nil {
		return TestResult{Success: false, Message: err.Error()}, nil
	}
	return TestResult{Success: true, Message: "tools/list succeeded"}, nil
}

// RevokeMCPOAuthApp clears OAuth app config and any credentials tied to it.
func (s *Service) RevokeMCPOAuthApp(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return err
	}
	if err := q.ClearMCPServerOAuthApp(ctx, dbq.ClearMCPServerOAuthAppParams{AgentID: toPg(agentID), Slug: slug}); err != nil {
		s.logger.Error("revoke MCP OAuth app failed", zap.Error(err))
		return err
	}
	return nil
}

// SetMCPOAuthApp stores encrypted client_id/client_secret for an MCP server.
func (s *Service) SetMCPOAuthApp(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, clientID, clientSecret string) (MCPStatus, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return MCPStatus{}, err
	}
	srv, err := q.GetMCPServerForOAuth(ctx, dbq.GetMCPServerForOAuthParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MCPStatus{}, service.Detail(service.ErrNotFound, "MCP server not found")
		}
		s.logger.Error("get MCP server failed", zap.Error(err))
		return MCPStatus{}, err
	}
	if srv.AuthMode != "oauth" && srv.AuthMode != "oauth_discovery" {
		return MCPStatus{}, service.Detail(service.ErrInvalidInput, "MCP server is not OAuth — use token endpoint")
	}
	srvRef := "mcp/" + uuid.UUID(srv.ID.Bytes).String()
	encClientID, err := s.encryptor.Put(ctx, srvRef+"/client_id", clientID)
	if err != nil {
		s.logger.Error("encrypt client_id failed", zap.Error(err))
		return MCPStatus{}, err
	}
	encClientSecret, err := s.encryptor.Put(ctx, srvRef+"/client_secret", clientSecret)
	if err != nil {
		s.logger.Error("encrypt client_secret failed", zap.Error(err))
		return MCPStatus{}, err
	}
	if err := q.UpdateMCPServerOAuthApp(ctx, dbq.UpdateMCPServerOAuthAppParams{
		AgentID: toPg(agentID), Slug: slug, ClientID: encClientID, ClientSecret: encClientSecret,
	}); err != nil {
		s.logger.Error("update MCP OAuth app failed", zap.Error(err))
		return MCPStatus{}, err
	}
	return MCPStatus{Slug: srv.Slug, Name: srv.Name, AuthMode: srv.AuthMode, Authorized: false}, nil
}

// MCPOAuthStart kicks off the OAuth dance for an MCP server. Includes
// lazy URL re-discovery and lazy DCR for oauth_discovery mode.
func (s *Service) MCPOAuthStart(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, redirectURI string) (string, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return "", err
	}
	srv, err := q.GetMCPServerForOAuth(ctx, dbq.GetMCPServerForOAuthParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", service.Detail(service.ErrNotFound, "MCP server not found")
		}
		s.logger.Error("get MCP server failed", zap.Error(err))
		return "", err
	}
	if srv.AuthMode != "oauth" && srv.AuthMode != "oauth_discovery" {
		return "", service.Detail(service.ErrInvalidInput, "MCP server is not OAuth")
	}
	if err := q.ClearMCPServerCredentials(ctx, dbq.ClearMCPServerCredentialsParams{AgentID: toPg(agentID), Slug: slug}); err != nil {
		s.logger.Error("clear stale MCP credentials failed", zap.Error(err))
		return "", err
	}
	needsDiscovery := srv.AuthMode == "oauth_discovery" &&
		(srv.AuthUrl == "" || srv.TokenUrl == "" ||
			(srv.ClientID == "" && srv.RegistrationEndpoint == ""))
	if needsDiscovery {
		result, derr := s.discoverAuth(ctx, srv.Url)
		if derr != nil {
			s.logger.Warn("MCP discovery retry failed", zap.String("slug", slug), zap.Error(derr))
			return "", service.Detail(service.ErrInvalidInput, "OAuth discovery failed: %s. The server's RFC 8414 metadata is unreachable or malformed; switch this MCP server's auth_mode to `oauth` and paste credentials manually.", derr.Error())
		}
		if result.AuthorizationURL != "" {
			srv.AuthUrl = result.AuthorizationURL
		}
		if result.TokenURL != "" {
			srv.TokenUrl = result.TokenURL
		}
		if result.RegistrationEndpoint != "" {
			srv.RegistrationEndpoint = result.RegistrationEndpoint
		}
		if err := q.UpdateMCPServerDiscovery(ctx, dbq.UpdateMCPServerDiscoveryParams{
			AgentID: toPg(agentID), Slug: slug,
			AuthUrl: srv.AuthUrl, TokenUrl: srv.TokenUrl, RegistrationEndpoint: srv.RegistrationEndpoint,
		}); err != nil {
			s.logger.Error("persist re-discovery failed", zap.Error(err))
			return "", err
		}
	}
	if srv.ClientID == "" && srv.AuthMode == "oauth_discovery" {
		if srv.RegistrationEndpoint == "" {
			return "", service.Detail(service.ErrInvalidInput,
				"server does not advertise an RFC 7591 registration endpoint. Switch this MCP server's auth_mode to `oauth` and paste credentials manually.")
		}
		callbackURL := s.publicURL + "/api/v1/credentials/oauth/callback"
		dcr, derr := oauth.RegisterClient(ctx, s.mcpHTTP, srv.RegistrationEndpoint, "airlock:"+srv.Name, callbackURL, srv.Scopes)
		if derr != nil {
			s.logger.Warn("MCP DCR failed", zap.String("slug", slug), zap.Error(derr))
			return "", service.Detail(service.ErrInvalidInput,
				"dynamic client registration failed: %s. Switch this MCP server's auth_mode to `oauth` and paste credentials manually.", derr.Error())
		}
		srvRef := "mcp/" + uuid.UUID(srv.ID.Bytes).String()
		encClientID, err := s.encryptor.Put(ctx, srvRef+"/client_id", dcr.ClientID)
		if err != nil {
			s.logger.Error("encrypt DCR client_id failed", zap.Error(err))
			return "", err
		}
		encClientSecret, err := s.encryptor.Put(ctx, srvRef+"/client_secret", dcr.ClientSecret)
		if err != nil {
			s.logger.Error("encrypt DCR client_secret failed", zap.Error(err))
			return "", err
		}
		if err := q.UpdateMCPServerOAuthApp(ctx, dbq.UpdateMCPServerOAuthAppParams{
			AgentID: toPg(agentID), Slug: slug,
			ClientID: encClientID, ClientSecret: encClientSecret,
		}); err != nil {
			s.logger.Error("persist DCR client failed", zap.Error(err))
			return "", err
		}
		srv.ClientID = encClientID
	}
	if srv.ClientID == "" {
		return "", service.Detail(service.ErrInvalidInput, "OAuth app not configured. Set client_id and client_secret first.")
	}
	clientID, err := s.encryptor.Get(ctx, "mcp/"+uuid.UUID(srv.ID.Bytes).String()+"/client_id", srv.ClientID)
	if err != nil {
		s.logger.Error("decrypt client_id failed", zap.Error(err))
		return "", err
	}
	verifier, challenge, err := oauth.GeneratePKCE()
	if err != nil {
		return "", err
	}
	state, err := oauth.GenerateState()
	if err != nil {
		return "", err
	}
	encVerifier, err := s.encryptor.Put(ctx, "oauth_state/"+state+"/code_verifier", verifier)
	if err != nil {
		return "", err
	}
	if err := q.CreateOAuthState(ctx, dbq.CreateOAuthStateParams{
		State: state, AgentID: toPg(agentID), Slug: slug,
		CodeVerifier: encVerifier, RedirectUri: redirectURI,
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(10 * time.Minute), Valid: true},
		SourceType: "mcp",
	}); err != nil {
		return "", err
	}
	callbackURL := s.publicURL + "/api/v1/credentials/oauth/callback"
	return s.oauthClient.BuildAuthURL(srv.AuthUrl, clientID, callbackURL, state, challenge, srv.Scopes, nil)
}

// --- env vars ---

// envVarRef is the canonical secrets.Store path for an env var value.
func envVarRef(id, slug string) string { return "agent/env-var/" + id + "/" + slug }

// ListEnvVars returns registered env vars with decrypted plain values
// (secrets stay write-only and return Value="").
func (s *Service) ListEnvVars(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]EnvVar, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListAgentEnvVars(ctx, toPg(agentID))
	if err != nil {
		s.logger.Error("list env vars failed", zap.Error(err))
		return nil, err
	}
	out := make([]EnvVar, 0, len(rows))
	for _, row := range rows {
		v := EnvVar{
			Slug: row.Slug, Description: row.Description, IsSecret: row.IsSecret,
			Configured: row.Configured, Pattern: row.Pattern, UpdatedAt: row.UpdatedAt.Time,
		}
		if !row.IsSecret {
			v.DefaultValue = row.DefaultValue
		}
		if row.Configured && !row.IsSecret {
			// Re-fetch row for value_ref; ListAgentEnvVars drops it on purpose.
			ref := ""
			if got, err := q.GetAgentEnvVarBySlug(ctx, dbq.GetAgentEnvVarBySlugParams{AgentID: toPg(agentID), Slug: row.Slug}); err == nil {
				ref = got.ValueRef
			}
			if value, derr := s.encryptor.Get(ctx, envVarRef(uuid.UUID(row.ID.Bytes).String(), row.Slug), ref); derr != nil {
				s.logger.Error("decrypt env var for list failed", zap.String("slug", row.Slug), zap.Error(derr))
			} else {
				v.Value = value
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// SetEnvVarValue validates against the slot's regex pattern (if any),
// encrypts, and persists.
func (s *Service) SetEnvVarValue(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, value string) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return err
	}
	row, err := q.GetAgentEnvVarBySlug(ctx, dbq.GetAgentEnvVarBySlugParams{AgentID: toPg(agentID), Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return service.Detail(service.ErrNotFound, "env var not registered")
		}
		s.logger.Error("get env var failed", zap.Error(err))
		return err
	}
	if row.Pattern != "" {
		re, perr := regexp.Compile(row.Pattern)
		if perr != nil {
			s.logger.Error("env var pattern invalid in DB", zap.String("slug", slug), zap.Error(perr))
			return fmt.Errorf("stored pattern is invalid")
		}
		if !re.MatchString(value) {
			return service.Detail(service.ErrInvalidInput, "value does not match required pattern")
		}
	}
	encRef, err := s.encryptor.Put(ctx, envVarRef(uuid.UUID(row.ID.Bytes).String(), slug), value)
	if err != nil {
		s.logger.Error("encrypt env var failed", zap.Error(err))
		return err
	}
	if err := q.SetAgentEnvVarValue(ctx, dbq.SetAgentEnvVarValueParams{
		AgentID: toPg(agentID), Slug: slug, ValueRef: encRef,
	}); err != nil {
		s.logger.Error("store env var value failed", zap.Error(err))
		return err
	}
	return nil
}

// ClearEnvVarValue clears the configured value (slot stays registered).
func (s *Service) ClearEnvVarValue(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return err
	}
	if err := q.ClearAgentEnvVarValue(ctx, dbq.ClearAgentEnvVarValueParams{AgentID: toPg(agentID), Slug: slug}); err != nil {
		s.logger.Error("clear env var failed", zap.Error(err))
		return err
	}
	return nil
}

// SetupStatus returns aggregate "needs operator action" counts.
func (s *Service) SetupStatus(ctx context.Context, p authz.Principal, agentID uuid.UUID) (SetupCounts, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return SetupCounts{}, err
	}
	row, err := q.AgentSetupStatus(ctx, toPg(agentID))
	if err != nil {
		s.logger.Error("setup status failed", zap.Error(err))
		return SetupCounts{}, err
	}
	return SetupCounts{
		Connections: row.Connections,
		MCPServers:  row.McpServers,
		EnvVars:     row.EnvVars,
	}, nil
}
