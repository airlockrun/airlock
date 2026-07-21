// Package connections owns reusable connection and MCP credentials, their
// need-aware OAuth lifecycle, agent env vars, and aggregate setup status.
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
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/networkpolicy"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/needs"
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

// resolveConn / resolveMCP map (agentID, need slug) to the bound resource row —
// the resource an agent reaches through its need's binding. Credential ops then
// address the resource by its id. An unbound need is "not found".
func (s *Service) resolveConn(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, slug string) (dbq.Connection, error) {
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: toPg(agentID), Type: "connection", Slug: slug})
	if err == nil && !need.BoundConnectionID.Valid {
		err = pgx.ErrNoRows
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.Connection{}, service.Detail(service.ErrNotFound, "connection not found")
		}
		return dbq.Connection{}, err
	}
	conn, err := q.GetConnectionByID(ctx, need.BoundConnectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.Connection{}, service.Detail(service.ErrNotFound, "connection not found")
	}
	return conn, err
}

func (s *Service) resolveMCP(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, slug string) (dbq.AgentMcpServer, error) {
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: toPg(agentID), Type: "mcp_server", Slug: slug})
	if err == nil && !need.BoundMcpID.Valid {
		err = pgx.ErrNoRows
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.AgentMcpServer{}, service.Detail(service.ErrNotFound, "MCP server not found")
		}
		return dbq.AgentMcpServer{}, err
	}
	srv, err := q.GetMCPServerByID(ctx, need.BoundMcpID)
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.AgentMcpServer{}, service.Detail(service.ErrNotFound, "MCP server not found")
	}
	return srv, err
}

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
	Connections   int32
	MCPServers    int32
	EnvVars       int32
	ExecEndpoints int32
}

// --- connections ---

// ensureBoundConnection makes sure a connection resource exists for the agent's
// declared need, creating it — owned by the configuring principal — and binding
// it on first credential configuration (idempotent if already bound). The
// provisioning is the shared needs.CreateForNeed step.
func (s *Service) ensureBoundConnection(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID, slug, displayName string, createNew bool) (uuid.UUID, error) {
	return needs.CreateForNeed(ctx, q, p, agentID, "connection", slug, displayName, createNew)
}

// SetOAuthApp persists encrypted client_id/client_secret for a connection.
func (s *Service) SetOAuthApp(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, displayName, clientID, clientSecret string, createNew bool) (Status, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return Status{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, toPg(agentID)); err != nil {
		return Status{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return Status{}, err
	}
	resourceID, err := s.ensureBoundConnection(ctx, q, p, agentID, slug, displayName, createNew)
	if err != nil {
		return Status{}, err
	}
	conn, err := q.GetConnectionByIDForUpdate(ctx, toPg(resourceID))
	if err != nil {
		return Status{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "connection", resourceID); err != nil {
		return Status{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, "connection", resourceID); err != nil {
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
	if _, err := q.StageConnectionOAuthAppByID(ctx, dbq.StageConnectionOAuthAppByIDParams{
		ID: conn.ID, ClientID: encClientID, ClientSecret: encClientSecret,
	}); err != nil {
		s.logger.Error("update oauth app failed", zap.Error(err))
		return Status{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Status{}, err
	}
	return Status{Slug: slug, Name: conn.Name, AuthMode: "oauth", Authorized: conn.AccessTokenRef != ""}, nil
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

// PublicURL exposes the configured public URL for handler URL synthesis.
func (s *Service) PublicURL() string { return s.publicURL }

func (s *Service) completionRedirect(raw string, agentID uuid.UUID) (string, error) {
	base, err := url.Parse(s.publicURL)
	if err != nil || !base.IsAbs() || base.Hostname() == "" {
		return "", errors.New("configured public URL is invalid")
	}
	if raw == "" {
		raw = fmt.Sprintf("/agents/%s", agentID)
	}
	target, err := url.Parse(raw)
	if err != nil || target.User != nil {
		return "", errors.New("redirect URL is invalid")
	}
	if !target.IsAbs() {
		if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
			return "", errors.New("relative redirect must start with one slash")
		}
		target = base.ResolveReference(target)
	}
	if !networkpolicy.SameOrigin(base, target) {
		return "", errors.New("redirect must have the Airlock origin")
	}
	return target.String(), nil
}

// refreshMCPAfterAuth re-discovers tools for a freshly-authorized MCP
// server and pushes the running agent container to re-sync. All steps
// are best-effort; the agent will pick up new tools on its next sync.
func (s *Service) refreshMCPAfterAuth(ctx context.Context, agentID uuid.UUID, slug, accessToken string) {
	q := dbq.New(s.db.Pool())
	srv, err := s.resolveMCP(ctx, q, agentID, slug)
	if err != nil {
		s.logger.Warn("refresh MCP: get server failed", zap.String("slug", slug), zap.Error(err))
		return
	}
	tools, instructions, err := s.discover(ctx, srv.Url, srv.AuthInjection, accessToken)
	if err != nil {
		s.logger.Warn("refresh MCP: discovery failed", zap.String("slug", slug), zap.Error(err))
	} else {
		schemasJSON, _ := json.Marshal(tools)
		if err := q.UpdateMCPServerToolSchemasByID(ctx, dbq.UpdateMCPServerToolSchemasByIDParams{
			ID: srv.ID, ToolSchemas: schemasJSON, ServerInstructions: instructions,
		}); err != nil {
			s.logger.Warn("refresh MCP: persist schemas failed", zap.String("slug", slug), zap.Error(err))
		}
	}
	if err := s.refresh(ctx, agentID); err != nil {
		s.logger.Warn("refresh MCP: agent /refresh failed", zap.String("agent", agentID.String()), zap.Error(err))
	}
}

// SetAPIKey stores an encrypted API key for a non-OAuth connection.
func (s *Service) SetAPIKey(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, displayName, apiKey string, createNew bool) (Status, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return Status{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, toPg(agentID)); err != nil {
		return Status{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return Status{}, err
	}
	resourceID, err := s.ensureBoundConnection(ctx, q, p, agentID, slug, displayName, createNew)
	if err != nil {
		return Status{}, err
	}
	conn, err := q.GetConnectionByID(ctx, toPg(resourceID))
	if err != nil {
		return Status{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "connection", resourceID); err != nil {
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
	if err := q.UpdateConnectionCredentialsByID(ctx, dbq.UpdateConnectionCredentialsByIDParams{
		ID: conn.ID, AccessTokenRef: encKey, GrantedScopes: "", ScopesVerified: false,
	}); err != nil {
		s.logger.Error("store API key failed", zap.Error(err))
		return Status{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Status{}, err
	}
	return Status{Slug: slug, Name: conn.Name, AuthMode: conn.AuthMode, Authorized: true}, nil
}

// ListConnections returns every connection registered against the agent.
func (s *Service) ListConnections(ctx context.Context, p authz.Principal, agentID uuid.UUID) (ConnectionsList, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentGet, agentID); err != nil {
		return ConnectionsList{}, err
	}
	rows, err := q.ListConnectionNeedsByAgent(ctx, toPg(agentID))
	if err != nil {
		s.logger.Error("list connections failed", zap.Error(err))
		return ConnectionsList{}, err
	}
	out := make([]Connection, len(rows))
	for i, c := range rows {
		out[i] = Connection{
			ID:                uuid.UUID(c.ConnectionID.Bytes),
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
	if err := authz.Authorize(ctx, q, p, authz.AgentGet, agentID); err != nil {
		return Status{}, err
	}
	conn, err := q.ResolveBoundConnection(ctx, dbq.ResolveBoundConnectionParams{AgentID: toPg(agentID), Slug: slug})
	if errors.Is(err, pgx.ErrNoRows) {
		// Unbound need: nothing configured yet, so it's unauthorized.
		return Status{Slug: slug, Authorized: false}, nil
	}
	if err != nil {
		s.logger.Error("get credential status failed", zap.Error(err))
		return Status{}, err
	}
	st := Status{
		Slug: conn.Slug, Name: conn.Name, AuthMode: conn.AuthMode,
		Authorized: conn.AuthMode == "none" || conn.AccessTokenRef != "",
	}
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
	conn, err := s.resolveConn(ctx, q, agentID, slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // nothing bound, nothing to revoke
	}
	if err != nil {
		s.logger.Error("resolve connection failed", zap.Error(err))
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "connection", uuid.UUID(conn.ID.Bytes)); err != nil {
		return err
	}
	affected, err := q.ClearConnectionCredentialsByID(ctx, conn.ID)
	if err != nil {
		s.logger.Error("revoke credential failed", zap.Error(err))
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
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
	conn, err := s.resolveConn(ctx, q, agentID, slug)
	if err != nil {
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
	if !strings.HasPrefix(conn.TestPath, "/") || strings.HasPrefix(conn.TestPath, "//") {
		return TestResult{}, service.Detail(service.ErrInvalidInput, "connection test path must start with one slash")
	}
	testURL := conn.BaseUrl + conn.TestPath
	baseURL, err := url.Parse(conn.BaseUrl)
	if err != nil {
		return TestResult{}, service.Detail(service.ErrInvalidInput, "invalid connection base URL")
	}
	upstream, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return TestResult{}, service.Detail(service.ErrInvalidInput, "invalid test URL")
	}
	if !networkpolicy.SameOrigin(baseURL, upstream.URL) {
		return TestResult{}, service.Detail(service.ErrInvalidInput, "connection test path changed the configured origin")
	}
	s.injectAuth(upstream, conn.AuthInjection, creds)
	resp, err := s.mcpHTTP.Do(upstream)
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
	if err := authz.Authorize(ctx, q, p, authz.AgentGet, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListMCPNeedsByAgent(ctx, toPg(agentID))
	if err != nil {
		s.logger.Error("list MCP servers failed", zap.Error(err))
		return nil, err
	}
	out := make([]MCPServer, len(rows))
	for i, m := range rows {
		ms := MCPServer{
			ID:          uuid.UUID(m.McpID.Bytes),
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
	if err := authz.Authorize(ctx, q, p, authz.AgentGet, agentID); err != nil {
		return MCPStatus{}, err
	}
	srv, err := q.ResolveBoundMCPServer(ctx, dbq.ResolveBoundMCPServerParams{AgentID: toPg(agentID), Slug: slug})
	if errors.Is(err, pgx.ErrNoRows) {
		return MCPStatus{Slug: slug, Authorized: false}, nil
	}
	if err != nil {
		s.logger.Error("get MCP server failed", zap.Error(err))
		return MCPStatus{}, err
	}
	return MCPStatus{
		Slug: srv.Slug, Name: srv.Name, AuthMode: srv.AuthMode,
		Authorized: srv.AccessTokenRef != "",
	}, nil
}

// SetMCPToken stores an encrypted token and re-discovers tools.
func (s *Service) SetMCPToken(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, displayName, apiKey string, createNew bool) (MCPStatus, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return MCPStatus{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, toPg(agentID)); err != nil {
		return MCPStatus{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return MCPStatus{}, err
	}
	resourceID, err := needs.CreateForNeed(ctx, q, p, agentID, "mcp_server", slug, displayName, createNew)
	if err != nil {
		return MCPStatus{}, err
	}
	srv, err := q.GetMCPServerByID(ctx, toPg(resourceID))
	if err != nil {
		return MCPStatus{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "mcp_server", resourceID); err != nil {
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
	if err := q.UpdateMCPServerCredentialsByID(ctx, dbq.UpdateMCPServerCredentialsByIDParams{
		ID: srv.ID, AccessTokenRef: encKey, GrantedScopes: "", ScopesVerified: false,
	}); err != nil {
		s.logger.Error("store MCP token failed", zap.Error(err))
		return MCPStatus{}, err
	}
	if err := tx.Commit(ctx); err != nil {
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
	srv, err := s.resolveMCP(ctx, q, agentID, slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // nothing bound, nothing to revoke
	}
	if err != nil {
		s.logger.Error("resolve MCP server failed", zap.Error(err))
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "mcp_server", uuid.UUID(srv.ID.Bytes)); err != nil {
		return err
	}
	affected, err := q.ClearMCPServerCredentialsByID(ctx, srv.ID)
	if err != nil {
		s.logger.Error("revoke MCP credential failed", zap.Error(err))
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	return nil
}

// TestMCPCredential probes the MCP server with tools/list.
func (s *Service) TestMCPCredential(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, overrideKey string) (TestResult, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return TestResult{}, err
	}
	srv, err := s.resolveMCP(ctx, q, agentID, slug)
	if err != nil {
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
	srv, err := s.resolveMCP(ctx, q, agentID, slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // nothing bound, nothing to revoke
	}
	if err != nil {
		s.logger.Error("resolve MCP server failed", zap.Error(err))
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "mcp_server", uuid.UUID(srv.ID.Bytes)); err != nil {
		return err
	}
	if err := q.ClearMCPServerOAuthAppByID(ctx, srv.ID); err != nil {
		s.logger.Error("revoke MCP OAuth app failed", zap.Error(err))
		return err
	}
	return nil
}

// SetMCPOAuthApp stores encrypted client_id/client_secret for an MCP server.
func (s *Service) SetMCPOAuthApp(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug, displayName, clientID, clientSecret string, createNew bool) (MCPStatus, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return MCPStatus{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, toPg(agentID)); err != nil {
		return MCPStatus{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentConnections, agentID); err != nil {
		return MCPStatus{}, err
	}
	resourceID, err := needs.CreateForNeed(ctx, q, p, agentID, "mcp_server", slug, displayName, createNew)
	if err != nil {
		return MCPStatus{}, err
	}
	srv, err := q.GetMCPServerByIDForUpdate(ctx, toPg(resourceID))
	if err != nil {
		return MCPStatus{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "mcp_server", resourceID); err != nil {
		return MCPStatus{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, "mcp_server", resourceID); err != nil {
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
	if _, err := q.StageMCPServerOAuthAppByID(ctx, dbq.StageMCPServerOAuthAppByIDParams{
		ID: srv.ID, ClientID: encClientID, ClientSecret: encClientSecret,
	}); err != nil {
		s.logger.Error("update MCP OAuth app failed", zap.Error(err))
		return MCPStatus{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return MCPStatus{}, err
	}
	return MCPStatus{Slug: srv.Slug, Name: srv.Name, AuthMode: srv.AuthMode, Authorized: srv.AccessTokenRef != ""}, nil
}

// --- env vars ---

// envVarRef is the canonical secrets.Store path for an env var value.
func envVarRef(id, slug string) string { return "agent/env-var/" + id + "/" + slug }

// ListEnvVars returns registered env vars with decrypted plain values
// (secrets stay write-only and return Value="").
func (s *Service) ListEnvVars(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]EnvVar, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentGet, agentID); err != nil {
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
	if err := authz.Authorize(ctx, q, p, authz.AgentGet, agentID); err != nil {
		return SetupCounts{}, err
	}
	row, err := q.AgentSetupStatus(ctx, toPg(agentID))
	if err != nil {
		s.logger.Error("setup status failed", zap.Error(err))
		return SetupCounts{}, err
	}
	return SetupCounts{
		Connections:   row.Connections,
		MCPServers:    row.McpServers,
		EnvVars:       row.EnvVars,
		ExecEndpoints: row.ExecEndpoints,
	}, nil
}
