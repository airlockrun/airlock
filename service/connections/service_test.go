package connections

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/db/dbtest"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

var callbackTestDB *db.DB

func TestMain(m *testing.M) {
	url, _, release, ok := dbtest.Setup(context.Background(), db.RunMigrations)
	if !ok {
		os.Exit(m.Run())
	}
	callbackTestDB = db.New(context.Background(), url)
	code := m.Run()
	callbackTestDB.Close()
	release()
	os.Exit(code)
}

func requireCallbackTestDB(t *testing.T) {
	t.Helper()
	if callbackTestDB == nil {
		t.Skip("no test database (Docker unavailable)")
	}
}

func testPGUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func callbackTestEncryptor() secrets.Store {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return secrets.NewLocal(crypto.New(key))
}

type oauthCallbackFixture struct {
	service    *Service
	provider   *httptest.Server
	queries    *dbq.Queries
	userID     uuid.UUID
	agentID    uuid.UUID
	resourceID uuid.UUID
	state      string
	exchanges  atomic.Int32
}

func newOAuthCallbackFixture(t *testing.T) *oauthCallbackFixture {
	return newOAuthCallbackFixtureWithExchange(t, nil)
}

func newOAuthCallbackFixtureWithExchange(t *testing.T, duringExchange func(*oauthCallbackFixture)) *oauthCallbackFixture {
	t.Helper()
	requireCallbackTestDB(t)
	ctx := t.Context()
	q := dbq.New(callbackTestDB.Pool())
	f := &oauthCallbackFixture{queries: q}
	f.provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.exchanges.Add(1)
		if duringExchange != nil {
			duringExchange(f)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token", "refresh_token": "refresh-token", "expires_in": 3600,
		})
	}))
	t.Cleanup(f.provider.Close)

	suffix := uuid.NewString()[:8]
	owner, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email: "callback-owner-" + suffix + "@example.com", DisplayName: "Callback Owner", TenantRole: "user",
	})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	user, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email: "callback-user-" + suffix + "@example.com", DisplayName: "Callback User", TenantRole: "manager",
	})
	if err != nil {
		t.Fatalf("create initiating user: %v", err)
	}
	agent, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name: "callback-" + suffix, Slug: "callback-" + suffix, OwnerPrincipalID: owner.ID, Config: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	for _, grantee := range []pgtype.UUID{owner.ID, user.ID} {
		if err := q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{AgentID: agent.ID, GranteeID: grantee, Role: "admin"}); err != nil {
			t.Fatalf("grant agent admin: %v", err)
		}
	}
	conn, err := q.UpsertConnection(ctx, dbq.UpsertConnectionParams{
		AgentID: agent.ID, Slug: "oauth", Name: "OAuth", DisplayName: "OAuth", AuthMode: "oauth",
		AuthUrl: f.provider.URL + "/authorize", TokenUrl: f.provider.URL + "/token", BaseUrl: f.provider.URL,
		AuthInjection: []byte(`{"type":"bearer"}`), Config: []byte("{}"), AuthParams: []byte("{}"), Headers: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if err := q.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
		AgentID: agent.ID, Type: "connection", Slug: "oauth", Description: "OAuth",
		ExpectedUrl: f.provider.URL, Spec: []byte(`{"base_url":"` + f.provider.URL + `","auth_mode":"oauth","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`),
	}); err != nil {
		t.Fatalf("create resource need: %v", err)
	}
	if _, err := q.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{AgentID: agent.ID, Slug: "oauth", ResourceID: conn.ID}); err != nil {
		t.Fatalf("bind connection: %v", err)
	}
	if _, err := callbackTestDB.Pool().Exec(ctx,
		`INSERT INTO resource_grants (connection_id, grantee_id, capabilities) VALUES ($1, $2, ARRAY['bind', 'manage'])`,
		conn.ID, user.ID); err != nil {
		t.Fatalf("grant resource authorization: %v", err)
	}

	enc := callbackTestEncryptor()
	resourceID := uuid.UUID(conn.ID.Bytes)
	ref := "connection/" + resourceID.String()
	clientID, err := enc.Put(ctx, ref+"/client_id", "client-id")
	if err != nil {
		t.Fatalf("encrypt client id: %v", err)
	}
	clientSecret, err := enc.Put(ctx, ref+"/client_secret", "client-secret")
	if err != nil {
		t.Fatalf("encrypt client secret: %v", err)
	}
	if _, err := q.StageConnectionOAuthAppByID(ctx, dbq.StageConnectionOAuthAppByIDParams{
		ID: conn.ID, ClientID: clientID, ClientSecret: clientSecret,
	}); err != nil {
		t.Fatalf("store OAuth app: %v", err)
	}
	if _, err := callbackTestDB.Pool().Exec(ctx, `UPDATE connections SET client_id=pending_client_id, client_secret=pending_client_secret, pending_client_id='', pending_client_secret='' WHERE id=$1`, conn.ID); err != nil {
		t.Fatalf("activate OAuth app fixture: %v", err)
	}

	f.userID = uuid.UUID(user.ID.Bytes)
	f.agentID = uuid.UUID(agent.ID.Bytes)
	f.resourceID = resourceID
	f.service = New(
		callbackTestDB, enc, oauth.NewClient(f.provider.Client(), true), "https://airlock.example",
		func(context.Context, uuid.UUID) error { return nil }, zap.NewNop(),
		func(context.Context, string, []byte, string) ([]ToolInfo, string, error) { return nil, "", nil },
		func(context.Context, string) (*oauth.DiscoveryResult, error) { return &oauth.DiscoveryResult{}, nil },
		func(*http.Request, []byte, string) {}, f.provider.Client(),
	)
	authorizeURL, err := f.service.OAuthStart(ctx, authz.UserPrincipal(f.userID, auth.RoleManager), f.agentID, "oauth", "")
	if err != nil {
		t.Fatalf("start OAuth: %v", err)
	}
	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	f.state = parsed.Query().Get("state")
	if f.state == "" {
		t.Fatal("OAuth start returned no state")
	}
	return f
}

func (f *oauthCallbackFixture) callback(t *testing.T) error {
	t.Helper()
	_, err := f.service.OAuthCallback(t.Context(), "authorization-code", f.state, "", "")
	return err
}

func (f *oauthCallbackFixture) assertNoExchangeOrCredential(t *testing.T, resourceID uuid.UUID) {
	t.Helper()
	if got := f.exchanges.Load(); got != 0 {
		t.Fatalf("token exchanges = %d, want 0", got)
	}
	conn, err := f.queries.GetConnectionByID(t.Context(), testPGUUID(resourceID))
	if err != nil {
		t.Fatalf("get connection: %v", err)
	}
	if conn.AccessTokenRef != "" || conn.RefreshToken != "" {
		t.Fatal("callback stored credentials after live authorization failed")
	}
}

func TestCompletionRedirect(t *testing.T) {
	service := &Service{publicURL: "https://airlock.example"}
	agentID := uuid.New()

	got, err := service.completionRedirect("/agents/custom?tab=connections", agentID)
	if err != nil {
		t.Fatalf("completionRedirect() error = %v", err)
	}
	if got != "https://airlock.example/agents/custom?tab=connections" {
		t.Fatalf("completionRedirect() = %q", got)
	}
	if _, err := service.completionRedirect("https://attacker.example/steal", agentID); err == nil {
		t.Fatal("completionRedirect() accepted an off-origin URL")
	}
	if _, err := service.completionRedirect("//attacker.example/steal", agentID); err == nil {
		t.Fatal("completionRedirect() accepted a scheme-relative URL")
	}
}

func TestOAuthCallbackRejectsMembershipRemovalOrDemotion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(context.Context, *oauthCallbackFixture) error
	}{
		{
			name: "membership removed",
			change: func(ctx context.Context, f *oauthCallbackFixture) error {
				return f.queries.DeleteAgentGrant(ctx, dbq.DeleteAgentGrantParams{
					AgentID: testPGUUID(f.agentID), GranteeID: testPGUUID(f.userID),
				})
			},
		},
		{
			name: "membership demoted",
			change: func(ctx context.Context, f *oauthCallbackFixture) error {
				return f.queries.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{
					AgentID: testPGUUID(f.agentID), GranteeID: testPGUUID(f.userID), Role: "user",
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOAuthCallbackFixture(t)
			if err := tc.change(t.Context(), f); err != nil {
				t.Fatalf("change membership: %v", err)
			}
			if err := f.callback(t); err != nil {
				t.Fatalf("OAuthCallback() error = %v", err)
			}
			f.assertNoExchangeOrCredential(t, f.resourceID)
		})
	}
}

func TestOAuthCallbackRejectsDeletedUser(t *testing.T) {
	f := newOAuthCallbackFixture(t)
	if _, err := callbackTestDB.Pool().Exec(t.Context(), `DELETE FROM users WHERE id = $1`, testPGUUID(f.userID)); err != nil {
		t.Fatalf("delete initiating user: %v", err)
	}
	if err := f.callback(t); !errors.Is(err, ErrOAuthInvalidState) {
		t.Fatalf("OAuthCallback() error = %v, want invalid state", err)
	}
	f.assertNoExchangeOrCredential(t, f.resourceID)
}

func TestOAuthCallbackRejectsResourceSubstitution(t *testing.T) {
	f := newOAuthCallbackFixture(t)
	replacement, err := f.queries.UpsertConnection(t.Context(), dbq.UpsertConnectionParams{
		AgentID: testPGUUID(f.agentID), Slug: "replacement", Name: "Replacement", DisplayName: "Replacement", AuthMode: "oauth",
		AuthUrl: f.provider.URL + "/authorize", TokenUrl: f.provider.URL + "/token", BaseUrl: f.provider.URL,
		AuthInjection: []byte(`{"type":"bearer"}`), Config: []byte("{}"), AuthParams: []byte("{}"), Headers: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("create replacement connection: %v", err)
	}
	if _, err := f.queries.BindConnectionNeed(t.Context(), dbq.BindConnectionNeedParams{
		AgentID: testPGUUID(f.agentID), Slug: "oauth", ResourceID: replacement.ID,
	}); err != nil {
		t.Fatalf("substitute bound connection: %v", err)
	}
	if err := f.callback(t); err != nil {
		t.Fatalf("OAuthCallback() error = %v", err)
	}
	f.assertNoExchangeOrCredential(t, f.resourceID)
	f.assertNoExchangeOrCredential(t, uuid.UUID(replacement.ID.Bytes))
}

func TestOAuthCallbackRejectsDeletedResource(t *testing.T) {
	f := newOAuthCallbackFixture(t)
	if affected, err := f.queries.DeleteConnectionByID(t.Context(), testPGUUID(f.resourceID)); err != nil {
		t.Fatalf("delete connection: %v", err)
	} else if affected != 1 {
		t.Fatalf("delete connection affected %d rows, want 1", affected)
	}
	if err := f.callback(t); err != nil {
		t.Fatalf("OAuthCallback() error = %v", err)
	}
	if got := f.exchanges.Load(); got != 0 {
		t.Fatalf("token exchanges = %d, want 0", got)
	}
}

func TestOAuthCallbackRechecksAuthorizationBeforeCredentialWrite(t *testing.T) {
	f := newOAuthCallbackFixtureWithExchange(t, func(f *oauthCallbackFixture) {
		if err := f.queries.DeleteAgentGrant(context.Background(), dbq.DeleteAgentGrantParams{
			AgentID: testPGUUID(f.agentID), GranteeID: testPGUUID(f.userID),
		}); err != nil {
			t.Errorf("remove membership during exchange: %v", err)
		}
	})
	if err := f.callback(t); err != nil {
		t.Fatalf("OAuthCallback() error = %v", err)
	}
	if got := f.exchanges.Load(); got != 1 {
		t.Fatalf("token exchanges = %d, want 1", got)
	}
	conn, err := f.queries.GetConnectionByID(t.Context(), testPGUUID(f.resourceID))
	if err != nil {
		t.Fatalf("get connection: %v", err)
	}
	if conn.AccessTokenRef != "" {
		t.Fatal("callback stored credentials after membership was removed during exchange")
	}
}
