package connections

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type authorizationFixture struct {
	service         *Service
	queries         *dbq.Queries
	provider        *httptest.Server
	principal       authz.Principal
	agentID         uuid.UUID
	resourceID      uuid.UUID
	targetSlug      string
	state           string
	tokenStatus     int
	tokenScope      *string
	refreshToken    *string
	exchanges       int
	registrations   int
	exchangeStarted chan struct{}
	releaseExchange chan struct{}
}

func newAuthorizationFixture(t *testing.T, existing bool) *authorizationFixture {
	t.Helper()
	requireCallbackTestDB(t)
	f := &authorizationFixture{queries: dbq.New(callbackTestDB.Pool()), tokenStatus: http.StatusOK, targetSlug: "target"}
	f.provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" {
			f.registrations++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": "dcr-client", "client_secret": "dcr-secret", "token_endpoint_auth_method": "client_secret_basic",
			})
			return
		}
		f.exchanges++
		if f.exchangeStarted != nil {
			close(f.exchangeStarted)
			<-f.releaseExchange
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.tokenStatus)
		if f.tokenStatus != http.StatusOK {
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
			return
		}
		response := map[string]any{"access_token": "new-access", "expires_in": 3600}
		if f.tokenScope != nil {
			response["scope"] = *f.tokenScope
		}
		if f.refreshToken != nil {
			response["refresh_token"] = *f.refreshToken
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(f.provider.Close)

	ctx := t.Context()
	suffix := uuid.NewString()[:8]
	user, err := f.queries.CreateUser(ctx, dbq.CreateUserParams{
		Email: "authorization-" + suffix + "@example.com", DisplayName: "Authorization Owner", TenantRole: "manager",
	})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := f.queries.CreateAgent(ctx, dbq.CreateAgentParams{
		Name: "authorization-" + suffix, Slug: "authorization-" + suffix, OwnerPrincipalID: user.ID, Config: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.queries.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{AgentID: agent.ID, GranteeID: user.ID, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	f.agentID = uuid.UUID(agent.ID.Bytes)
	f.principal = authz.UserPrincipal(uuid.UUID(user.ID.Bytes), auth.RoleManager)
	needSpec := func(scopes string) []byte {
		return []byte(`{"name":"Provider","base_url":"` + f.provider.URL + `","auth_mode":"oauth","auth_url":"` + f.provider.URL + `/authorize","token_url":"` + f.provider.URL + `/token","scopes":"` + scopes + `","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`)
	}
	if existing {
		resource, err := f.queries.UpsertConnection(ctx, dbq.UpsertConnectionParams{
			AgentID: agent.ID, Slug: "existing", Name: "Provider", DisplayName: "Provider",
			AuthMode: "oauth", AuthUrl: f.provider.URL + "/authorize", TokenUrl: f.provider.URL + "/token", BaseUrl: f.provider.URL,
			Scopes: "read", AuthInjection: []byte(`{"type":"bearer"}`), Config: []byte("{}"), AuthParams: []byte("{}"), Headers: []byte("{}"),
		})
		if err != nil {
			t.Fatal(err)
		}
		f.resourceID = uuid.UUID(resource.ID.Bytes)
		if err := f.queries.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
			AgentID: agent.ID, Type: "connection", Slug: "existing", Description: "Existing",
			ExpectedUrl: f.provider.URL, ExpectedScopes: "read", Spec: needSpec("read"),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.queries.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{AgentID: agent.ID, Slug: "existing", ResourceID: resource.ID}); err != nil {
			t.Fatal(err)
		}
		enc := callbackTestEncryptor()
		ref := "connection/" + f.resourceID.String()
		clientID, _ := enc.Put(ctx, ref+"/client_id", "client-id")
		clientSecret, _ := enc.Put(ctx, ref+"/client_secret", "client-secret")
		oldAccess, _ := enc.Put(ctx, ref+"/access_token", "old-access")
		oldRefresh, _ := enc.Put(ctx, ref+"/refresh_token", "old-refresh")
		if _, err := f.queries.StageConnectionOAuthAppByID(ctx, dbq.StageConnectionOAuthAppByIDParams{ID: resource.ID, ClientID: clientID, ClientSecret: clientSecret}); err != nil {
			t.Fatal(err)
		}
		if _, err := callbackTestDB.Pool().Exec(ctx, `UPDATE connections SET client_id=pending_client_id, client_secret=pending_client_secret, pending_client_id='', pending_client_secret='' WHERE id=$1`, resource.ID); err != nil {
			t.Fatal(err)
		}
		if err := f.queries.UpdateConnectionCredentialsByID(ctx, dbq.UpdateConnectionCredentialsByIDParams{
			ID: resource.ID, AccessTokenRef: oldAccess, RefreshToken: oldRefresh, GrantedScopes: "read", ScopesVerified: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.queries.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
		AgentID: agent.ID, Type: "connection", Slug: f.targetSlug, Description: "Target",
		ExpectedUrl: f.provider.URL, ExpectedScopes: "read write", Spec: needSpec("write read"),
	}); err != nil {
		t.Fatal(err)
	}
	enc := callbackTestEncryptor()
	f.service = New(
		callbackTestDB, enc, oauth.NewClient(f.provider.Client(), true), "https://airlock.example",
		func(context.Context, uuid.UUID) error { return nil }, zap.NewNop(),
		func(context.Context, string, []byte, string) ([]ToolInfo, string, error) { return nil, "", nil },
		func(context.Context, string) (*oauth.DiscoveryResult, error) { return &oauth.DiscoveryResult{}, nil },
		func(*http.Request, []byte, string) {}, f.provider.Client(),
	)
	return f
}

func prepareRefreshFixture(t *testing.T) *authorizationFixture {
	t.Helper()
	f := newAuthorizationFixture(t, true)
	if _, err := callbackTestDB.Pool().Exec(t.Context(), `UPDATE agents SET status='active' WHERE id=$1`, pgUUID(f.agentID)); err != nil {
		t.Fatal(err)
	}
	resource, err := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.queries.UpdateConnectionCredentialsByID(t.Context(), dbq.UpdateConnectionCredentialsByIDParams{
		ID: resource.ID, AccessTokenRef: resource.AccessTokenRef, RefreshToken: resource.RefreshToken,
		GrantedScopes: "read", ScopesVerified: true, TokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDormantOAuthRefreshExclusionAndRebind(t *testing.T) {
	f := prepareRefreshFixture(t)
	if _, err := f.queries.UnbindResourceNeed(t.Context(), dbq.UnbindResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: "existing"}); err != nil {
		t.Fatal(err)
	}
	eligible, err := oauth.RefreshConnectionTokenIfEligible(t.Context(), callbackTestDB, callbackTestEncryptor(), f.service.oauthClient, zap.NewNop(), pgUUID(f.resourceID), time.Now())
	if err != nil || eligible || f.exchanges != 0 {
		t.Fatalf("orphan refresh: eligible=%v exchanges=%d err=%v", eligible, f.exchanges, err)
	}
	if _, err := f.queries.BindConnectionNeed(t.Context(), dbq.BindConnectionNeedParams{AgentID: pgUUID(f.agentID), Slug: "existing", ResourceID: pgUUID(f.resourceID)}); err != nil {
		t.Fatal(err)
	}
	eligible, err = oauth.RefreshConnectionTokenIfEligible(t.Context(), callbackTestDB, callbackTestEncryptor(), f.service.oauthClient, zap.NewNop(), pgUUID(f.resourceID), time.Now())
	if err != nil || !eligible || f.exchanges != 1 {
		t.Fatalf("rebound refresh: eligible=%v exchanges=%d err=%v", eligible, f.exchanges, err)
	}
}

func TestRefreshLocksQualifyingBindingThroughCredentialWrite(t *testing.T) {
	f := prepareRefreshFixture(t)
	f.exchangeStarted = make(chan struct{})
	f.releaseExchange = make(chan struct{})
	refreshDone := make(chan error, 1)
	go func() {
		_, err := oauth.RefreshConnectionTokenIfEligible(context.Background(), callbackTestDB, callbackTestEncryptor(), f.service.oauthClient, zap.NewNop(), pgUUID(f.resourceID), time.Now())
		refreshDone <- err
	}()
	<-f.exchangeStarted
	unbound := make(chan error, 1)
	go func() {
		_, err := f.queries.UnbindResourceNeed(context.Background(), dbq.UnbindResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: "existing"})
		unbound <- err
	}()
	select {
	case err := <-unbound:
		t.Fatalf("unbind completed before refresh transaction: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(f.releaseExchange)
	if err := <-refreshDone; err != nil {
		t.Fatal(err)
	}
	if err := <-unbound; err != nil {
		t.Fatal(err)
	}
}

func TestValidTokenWaitsForConcurrentScopeExpansionAndRechecksNeed(t *testing.T) {
	f := newAuthorizationFixture(t, true)
	tx, err := callbackTestDB.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	qtx := dbq.New(tx)
	if _, err := qtx.GetAgentByIDForUpdate(t.Context(), pgUUID(f.agentID)); err != nil {
		t.Fatal(err)
	}
	need, err := qtx.GetResourceNeedForUpdate(t.Context(), dbq.GetResourceNeedForUpdateParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: "existing"})
	if err != nil {
		t.Fatal(err)
	}
	if err := qtx.UpsertResourceNeed(t.Context(), dbq.UpsertResourceNeedParams{
		AgentID: need.AgentID, Type: need.Type, Slug: need.Slug, Description: need.Description,
		SetupInstructions: need.SetupInstructions, ExpectedUrl: need.ExpectedUrl, ExpectedScopes: "read write", Spec: need.Spec,
	}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := oauth.EnsureConnectionToken(context.Background(), callbackTestDB, callbackTestEncryptor(), f.service.oauthClient, zap.NewNop(), pgUUID(f.agentID), "existing", pgUUID(f.resourceID), time.Now())
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("token check completed before scope sync committed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, oauth.ErrNeedsReauth) {
		t.Fatalf("EnsureConnectionToken() error = %v, want ErrNeedsReauth", err)
	}
	if f.exchanges != 0 {
		t.Fatalf("valid token path performed %d exchanges", f.exchanges)
	}
}

func (f *authorizationFixture) start(t *testing.T) {
	t.Helper()
	started, err := f.service.StartAuthorizationForNeed(t.Context(), f.principal, f.agentID, "connection", f.targetSlug, f.resourceID, "Provider", "", false)
	if err != nil {
		t.Fatalf("start authorization: %v", err)
	}
	f.resourceID = started.ResourceID
	state, err := f.queries.GetOAuthStateForResource(t.Context(), pgUUID(f.resourceID))
	if err != nil {
		t.Fatalf("load OAuth state: %v", err)
	}
	f.state = state.State
}

func (f *authorizationFixture) callback(t *testing.T) OAuthCallbackResult {
	t.Helper()
	result, err := f.service.OAuthCallback(t.Context(), "code", f.state, "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return result
}

func (f *authorizationFixture) assertOldCredentialAndUnbound(t *testing.T) {
	t.Helper()
	resource, err := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID))
	if err != nil {
		t.Fatal(err)
	}
	access, err := callbackTestEncryptor().Get(t.Context(), "connection/"+f.resourceID.String()+"/access_token", resource.AccessTokenRef)
	if err != nil || access != "old-access" || resource.GrantedScopes != "read" {
		t.Fatalf("active credential changed: access=%q scopes=%q err=%v", access, resource.GrantedScopes, err)
	}
	need, err := f.queries.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: f.targetSlug})
	if err != nil || need.BoundConnectionID.Valid {
		t.Fatalf("target binding changed: %+v, %v", need, err)
	}
}

func TestExistingOAuthExpansionBindsAtomically(t *testing.T) {
	f := newAuthorizationFixture(t, true)
	f.start(t)
	f.callback(t)
	resource, err := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID))
	if err != nil {
		t.Fatal(err)
	}
	access, _ := callbackTestEncryptor().Get(t.Context(), "connection/"+f.resourceID.String()+"/access_token", resource.AccessTokenRef)
	refresh, _ := callbackTestEncryptor().Get(t.Context(), "connection/"+f.resourceID.String()+"/refresh_token", resource.RefreshToken)
	if access != "new-access" || refresh != "old-refresh" || resource.GrantedScopes != "read write" || !resource.ScopesVerified {
		t.Fatalf("stored credential: access=%q refresh=%q scopes=%q verified=%v", access, refresh, resource.GrantedScopes, resource.ScopesVerified)
	}
	need, err := f.queries.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: f.targetSlug})
	if err != nil || !need.BoundConnectionID.Valid || uuid.UUID(need.BoundConnectionID.Bytes) != f.resourceID {
		t.Fatalf("target not bound atomically: %+v, %v", need, err)
	}
}

func TestExistingOAuthExpansionFailuresPreserveCredential(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*authorizationFixture)
		call   func(*authorizationFixture, *testing.T)
	}{
		{name: "denied", call: func(f *authorizationFixture, t *testing.T) {
			if _, err := f.service.OAuthCallback(t.Context(), "", f.state, "access_denied", "denied"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "exchange failure", change: func(f *authorizationFixture) { f.tokenStatus = http.StatusInternalServerError }, call: func(f *authorizationFixture, t *testing.T) { f.callback(t) }},
		{name: "partial grant", change: func(f *authorizationFixture) { scope := "read"; f.tokenScope = &scope }, call: func(f *authorizationFixture, t *testing.T) { f.callback(t) }},
		{name: "stale start", call: func(f *authorizationFixture, t *testing.T) {
			oldState := f.state
			f.start(t)
			if _, err := f.service.OAuthCallback(t.Context(), "code", oldState, "", ""); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthorizationFixture(t, true)
			f.start(t)
			if tc.change != nil {
				tc.change(f)
			}
			tc.call(f, t)
			f.assertOldCredentialAndUnbound(t)
		})
	}
}

func TestOAuthCallbackCannotResurrectRevokedCredential(t *testing.T) {
	f := newAuthorizationFixture(t, true)
	f.start(t)
	f.exchangeStarted = make(chan struct{})
	f.releaseExchange = make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		_, err := f.service.OAuthCallback(context.Background(), "code", f.state, "", "")
		callbackDone <- err
	}()
	<-f.exchangeStarted
	if _, err := f.queries.ClearConnectionCredentialsByID(t.Context(), pgUUID(f.resourceID)); err != nil {
		t.Fatal(err)
	}
	close(f.releaseExchange)
	if err := <-callbackDone; err != nil {
		t.Fatal(err)
	}
	resource, err := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID))
	if err != nil {
		t.Fatal(err)
	}
	if resource.AccessTokenRef != "" || resource.RefreshToken != "" || resource.GrantedScopes != "" {
		t.Fatalf("callback resurrected revoked credentials: %+v", resource)
	}
	need, err := f.queries.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: f.targetSlug})
	if err != nil || need.BoundConnectionID.Valid {
		t.Fatalf("callback bound target after revoke: %+v, %v", need, err)
	}
}

func TestOAuthCallbackUsesFinalLockedRefreshReference(t *testing.T) {
	f := newAuthorizationFixture(t, true)
	f.start(t)
	f.exchangeStarted = make(chan struct{})
	f.releaseExchange = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := f.service.OAuthCallback(context.Background(), "code", f.state, "", "")
		done <- err
	}()
	<-f.exchangeStarted
	resource, err := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID))
	if err != nil {
		t.Fatal(err)
	}
	newerRefresh, err := callbackTestEncryptor().Put(t.Context(), "connection/"+f.resourceID.String()+"/refresh_token", "newer-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.queries.UpdateConnectionCredentialsByID(t.Context(), dbq.UpdateConnectionCredentialsByIDParams{
		ID: resource.ID, AccessTokenRef: resource.AccessTokenRef, RefreshToken: newerRefresh,
		GrantedScopes: resource.GrantedScopes, ScopesVerified: resource.ScopesVerified, TokenExpiresAt: resource.TokenExpiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	close(f.releaseExchange)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	resource, _ = f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID))
	refresh, err := callbackTestEncryptor().Get(t.Context(), "connection/"+f.resourceID.String()+"/refresh_token", resource.RefreshToken)
	if err != nil || refresh != "newer-refresh" {
		t.Fatalf("refresh token = %q, err=%v", refresh, err)
	}
}

func TestNewOAuthProvisionalLifecycle(t *testing.T) {
	t.Run("success activates and binds", func(t *testing.T) {
		f := newAuthorizationFixture(t, false)
		if _, err := f.service.SetOAuthApp(t.Context(), f.principal, f.agentID, f.targetSlug, "Provider", "client-id", "client-secret", false); err != nil {
			t.Fatal(err)
		}
		need, _ := f.queries.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: f.targetSlug})
		provisional, err := f.queries.GetProvisionalConnectionForNeedOwner(t.Context(), dbq.GetProvisionalConnectionForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: pgUUID(f.principal.UserID)})
		if err != nil || provisional.Lifecycle != "provisional" || need.BoundConnectionID.Valid {
			t.Fatalf("provisional state = %+v need=%+v err=%v", provisional, need, err)
		}
		inventory, err := f.queries.ListAvailableConnections(t.Context(), []pgtype.UUID{pgUUID(f.principal.UserID)})
		if err != nil || len(inventory) != 0 {
			t.Fatalf("provisional leaked into inventory: %v, %v", inventory, err)
		}
		f.start(t)
		f.callback(t)
		active, err := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID))
		if err != nil || active.Lifecycle != "active" || active.ProvisionalNeedID.Valid {
			t.Fatalf("active resource = %+v, %v", active, err)
		}
	})

	t.Run("denial deletes provisional", func(t *testing.T) {
		f := newAuthorizationFixture(t, false)
		if _, err := f.service.SetOAuthApp(t.Context(), f.principal, f.agentID, f.targetSlug, "Provider", "client-id", "client-secret", false); err != nil {
			t.Fatal(err)
		}
		f.start(t)
		if _, err := f.service.OAuthCallback(t.Context(), "", f.state, "access_denied", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID)); err != pgx.ErrNoRows {
			t.Fatalf("provisional remains after denial: %v", err)
		}
	})

	t.Run("exchange failure deletes provisional", func(t *testing.T) {
		f := newAuthorizationFixture(t, false)
		if _, err := f.service.SetOAuthApp(t.Context(), f.principal, f.agentID, f.targetSlug, "Provider", "client-id", "client-secret", false); err != nil {
			t.Fatal(err)
		}
		f.start(t)
		f.tokenStatus = http.StatusInternalServerError
		f.callback(t)
		if _, err := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID)); err != pgx.ErrNoRows {
			t.Fatalf("provisional remains after exchange failure: %v", err)
		}
	})

	t.Run("expiry deletes provisional", func(t *testing.T) {
		f := newAuthorizationFixture(t, false)
		if _, err := f.service.SetOAuthApp(t.Context(), f.principal, f.agentID, f.targetSlug, "Provider", "client-id", "client-secret", false); err != nil {
			t.Fatal(err)
		}
		f.start(t)
		if _, err := callbackTestDB.Pool().Exec(t.Context(), `UPDATE oauth_states SET expires_at=$1 WHERE state=$2`, time.Now().Add(-time.Minute), f.state); err != nil {
			t.Fatal(err)
		}
		if _, err := callbackTestDB.Pool().Exec(t.Context(), `UPDATE connections SET updated_at=$1 WHERE id=$2`, time.Now().Add(-11*time.Minute), pgUUID(f.resourceID)); err != nil {
			t.Fatal(err)
		}
		if err := f.queries.CleanupExpiredOAuthStates(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := f.queries.CleanupAbandonedProvisionalConnections(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID)); err != pgx.ErrNoRows {
			t.Fatalf("provisional remains after expiry: %v", err)
		}
	})
}

func TestOAuthCreateNewSwitchesOnlyAfterSuccess(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		f := newAuthorizationFixture(t, true)
		if _, err := f.queries.BindConnectionNeed(t.Context(), dbq.BindConnectionNeedParams{AgentID: pgUUID(f.agentID), Slug: f.targetSlug, ResourceID: pgUUID(f.resourceID)}); err != nil {
			t.Fatal(err)
		}
		oldID := f.resourceID
		if _, err := f.service.SetOAuthApp(t.Context(), f.principal, f.agentID, f.targetSlug, "Replacement", "new-client", "new-secret", true); err != nil {
			t.Fatal(err)
		}
		need, err := f.queries.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: f.targetSlug})
		if err != nil || uuid.UUID(need.BoundConnectionID.Bytes) != oldID {
			t.Fatalf("binding moved before authorization: %+v, %v", need, err)
		}
		started, err := f.service.StartAuthorizationForNeed(t.Context(), f.principal, f.agentID, "connection", f.targetSlug, uuid.Nil, "", "", true)
		if err != nil {
			t.Fatal(err)
		}
		if started.ResourceID == oldID {
			t.Fatal("create_new targeted the bound resource")
		}
		f.resourceID = started.ResourceID
		state, _ := f.queries.GetOAuthStateForResource(t.Context(), pgUUID(f.resourceID))
		f.state = state.State
		f.callback(t)
		need, _ = f.queries.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: f.targetSlug})
		if uuid.UUID(need.BoundConnectionID.Bytes) != f.resourceID {
			t.Fatalf("callback did not switch binding: %+v", need)
		}
		old, _ := f.queries.GetConnectionByID(t.Context(), pgUUID(oldID))
		access, _ := callbackTestEncryptor().Get(t.Context(), "connection/"+oldID.String()+"/access_token", old.AccessTokenRef)
		if access != "old-access" {
			t.Fatalf("old resource credentials changed: %q", access)
		}
	})

	t.Run("denial preserves prior binding", func(t *testing.T) {
		f := newAuthorizationFixture(t, true)
		oldID := f.resourceID
		if _, err := f.queries.BindConnectionNeed(t.Context(), dbq.BindConnectionNeedParams{AgentID: pgUUID(f.agentID), Slug: f.targetSlug, ResourceID: pgUUID(oldID)}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.SetOAuthApp(t.Context(), f.principal, f.agentID, f.targetSlug, "Replacement", "new-client", "new-secret", true); err != nil {
			t.Fatal(err)
		}
		started, err := f.service.StartAuthorizationForNeed(t.Context(), f.principal, f.agentID, "connection", f.targetSlug, uuid.Nil, "", "", true)
		if err != nil {
			t.Fatal(err)
		}
		state, _ := f.queries.GetOAuthStateForResource(t.Context(), pgUUID(started.ResourceID))
		if _, err := f.service.OAuthCallback(t.Context(), "", state.State, "access_denied", ""); err != nil {
			t.Fatal(err)
		}
		need, _ := f.queries.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: f.targetSlug})
		if uuid.UUID(need.BoundConnectionID.Bytes) != oldID {
			t.Fatalf("denial changed binding: %+v", need)
		}
	})
}

func TestOAuthAppReplacementIsStaged(t *testing.T) {
	for _, success := range []bool{false, true} {
		name := "failure preserves active app"
		if success {
			name = "success swaps app and token"
		}
		t.Run(name, func(t *testing.T) {
			f := newAuthorizationFixture(t, true)
			if _, err := f.service.SetOAuthApp(t.Context(), f.principal, f.agentID, "existing", "", "replacement-client", "replacement-secret", false); err != nil {
				t.Fatal(err)
			}
			resource, _ := f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID))
			access, _ := callbackTestEncryptor().Get(t.Context(), "connection/"+f.resourceID.String()+"/access_token", resource.AccessTokenRef)
			activeClient, _ := callbackTestEncryptor().Get(t.Context(), "connection/"+f.resourceID.String()+"/client_id", resource.ClientID)
			if access != "old-access" || activeClient != "client-id" || resource.PendingClientID == "" {
				t.Fatalf("replacement disturbed active credentials: access=%q client=%q pending=%q", access, activeClient, resource.PendingClientID)
			}
			started, err := f.service.StartAuthorizationForNeed(t.Context(), f.principal, f.agentID, "connection", "existing", f.resourceID, "", "", false)
			if err != nil {
				t.Fatal(err)
			}
			state, _ := f.queries.GetOAuthStateForResource(t.Context(), pgUUID(started.ResourceID))
			if success {
				if _, err := f.service.OAuthCallback(t.Context(), "code", state.State, "", ""); err != nil {
					t.Fatal(err)
				}
			} else if _, err := f.service.OAuthCallback(t.Context(), "", state.State, "access_denied", ""); err != nil {
				t.Fatal(err)
			}
			resource, _ = f.queries.GetConnectionByID(t.Context(), pgUUID(f.resourceID))
			activeClient, _ = callbackTestEncryptor().Get(t.Context(), "connection/"+f.resourceID.String()+"/client_id", resource.ClientID)
			access, _ = callbackTestEncryptor().Get(t.Context(), "connection/"+f.resourceID.String()+"/access_token", resource.AccessTokenRef)
			if success && (activeClient != "replacement-client" || access != "new-access" || resource.PendingClientID != "") {
				t.Fatalf("successful replacement not activated: client=%q access=%q pending=%q", activeClient, access, resource.PendingClientID)
			}
			if !success && (activeClient != "client-id" || access != "old-access" || resource.PendingClientID != "") {
				t.Fatalf("failed replacement changed active state: client=%q access=%q pending=%q", activeClient, access, resource.PendingClientID)
			}
		})
	}
}

func TestSetupStatusCountsBindingScopesExecAndOptionalNeeds(t *testing.T) {
	f := newAuthorizationFixture(t, true)
	ctx := t.Context()
	if _, err := f.queries.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{AgentID: pgUUID(f.agentID), Slug: f.targetSlug, ResourceID: pgUUID(f.resourceID)}); err != nil {
		t.Fatal(err)
	}
	if err := f.queries.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(f.agentID), Type: "connection", Slug: "public-unbound", Description: "Public", Spec: []byte(`{"name":"Public","auth_mode":"none"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.queries.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(f.agentID), Type: "connection", Slug: "optional", Description: "Optional", Spec: []byte(`{"name":"Optional","auth_mode":"token"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := callbackTestDB.Pool().Exec(ctx, `UPDATE agent_resource_needs SET required=false WHERE agent_id=$1 AND slug='optional'`, pgUUID(f.agentID)); err != nil {
		t.Fatal(err)
	}
	if err := f.queries.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(f.agentID), Type: "mcp_server", Slug: "mcp", Description: "MCP", Spec: []byte(`{"name":"MCP","auth_mode":"none"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.queries.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(f.agentID), Type: "exec_endpoint", Slug: "shell", Description: "Shell", Spec: []byte(`{"access":"admin"}`),
	}); err != nil {
		t.Fatal(err)
	}
	counts, err := f.service.SetupStatus(ctx, f.principal, f.agentID)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Connections != 2 || counts.MCPServers != 1 || counts.ExecEndpoints != 1 {
		t.Fatalf("setup counts = %+v, want connections=2 mcp=1 exec=1", counts)
	}
}

func TestOAuthProvisionalsAreUniquePerNeedAndOwner(t *testing.T) {
	f := newAuthorizationFixture(t, false)
	other, err := f.queries.CreateUser(t.Context(), dbq.CreateUserParams{
		Email: "coadmin-" + uuid.NewString()[:8] + "@example.com", DisplayName: "Co-admin", TenantRole: "manager",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.queries.UpsertAgentGrant(t.Context(), dbq.UpsertAgentGrantParams{AgentID: pgUUID(f.agentID), GranteeID: other.ID, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.SetOAuthApp(t.Context(), f.principal, f.agentID, f.targetSlug, "Owner resource", "owner-client", "secret", true); err != nil {
		t.Fatal(err)
	}
	otherPrincipal := authz.UserPrincipal(uuid.UUID(other.ID.Bytes), auth.RoleManager)
	if _, err := f.service.SetOAuthApp(t.Context(), otherPrincipal, f.agentID, f.targetSlug, "Co-admin resource", "coadmin-client", "secret", true); err != nil {
		t.Fatal(err)
	}
	need, _ := f.queries.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "connection", Slug: f.targetSlug})
	first, err := f.queries.GetProvisionalConnectionForNeedOwner(t.Context(), dbq.GetProvisionalConnectionForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: pgUUID(f.principal.UserID)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.queries.GetProvisionalConnectionForNeedOwner(t.Context(), dbq.GetProvisionalConnectionForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: other.ID})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("co-admins shared one provisional resource")
	}
}

func TestMCPOAuthProvisionalLifecycle(t *testing.T) {
	for _, mode := range []string{"oauth", "oauth_discovery"} {
		for _, outcome := range []string{"success", "denial", "partial grant"} {
			t.Run(mode+"/"+outcome, func(t *testing.T) {
				f := newAuthorizationFixture(t, false)
				f.targetSlug = "mcp-target"
				f.service.discoverAuth = func(context.Context, string) (*oauth.DiscoveryResult, error) {
					return &oauth.DiscoveryResult{
						AuthorizationURL: f.provider.URL + "/authorize", TokenURL: f.provider.URL + "/token",
						RegistrationEndpoint: f.provider.URL + "/register",
					}, nil
				}
				q := f.queries
				spec := []byte(`{"name":"MCP Provider","url":"` + f.provider.URL + `","auth_mode":"` + mode + `","auth_url":"` + f.provider.URL + `/authorize","token_url":"` + f.provider.URL + `/token","scopes":"read write","auth_injection":{"type":"bearer"}}`)
				if err := q.UpsertResourceNeed(t.Context(), dbq.UpsertResourceNeedParams{
					AgentID: pgUUID(f.agentID), Type: "mcp_server", Slug: f.targetSlug, Description: "MCP target",
					ExpectedUrl: f.provider.URL, ExpectedScopes: "read write", Spec: spec,
				}); err != nil {
					t.Fatal(err)
				}
				prior, err := q.UpsertMCPServer(t.Context(), dbq.UpsertMCPServerParams{
					AgentID: pgUUID(f.agentID), Slug: "prior-mcp", Name: "Prior MCP", DisplayName: "Prior MCP",
					Url: f.provider.URL, AuthMode: mode, AuthUrl: f.provider.URL + "/authorize", TokenUrl: f.provider.URL + "/token",
					RegistrationEndpoint: f.provider.URL + "/register", Scopes: "read write", Access: "admin", AuthInjection: []byte(`{"type":"bearer"}`),
				})
				if err != nil {
					t.Fatal(err)
				}
				priorID := uuid.UUID(prior.ID.Bytes)
				priorAccess, err := callbackTestEncryptor().Put(t.Context(), "mcp/"+priorID.String()+"/access_token", "prior-mcp-access")
				if err != nil {
					t.Fatal(err)
				}
				if err := q.UpdateMCPServerCredentialsByID(t.Context(), dbq.UpdateMCPServerCredentialsByIDParams{
					ID: prior.ID, AccessTokenRef: priorAccess, GrantedScopes: "read", ScopesVerified: true,
				}); err != nil {
					t.Fatal(err)
				}
				if _, err := q.BindMCPServerNeed(t.Context(), dbq.BindMCPServerNeedParams{
					AgentID: pgUUID(f.agentID), Slug: f.targetSlug, ResourceID: prior.ID,
				}); err != nil {
					t.Fatal(err)
				}

				if mode == "oauth" {
					if _, err := f.service.SetMCPOAuthApp(t.Context(), f.principal, f.agentID, f.targetSlug, "Replacement MCP", "manual-client", "manual-secret", true); err != nil {
						t.Fatal(err)
					}
				}
				started, err := f.service.StartAuthorizationForNeed(t.Context(), f.principal, f.agentID, "mcp_server", f.targetSlug, uuid.Nil, "Replacement MCP", "", true)
				if err != nil {
					t.Fatal(err)
				}
				if started.ResourceID == priorID {
					t.Fatal("create_new targeted prior MCP resource")
				}
				need, err := q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "mcp_server", Slug: f.targetSlug})
				if err != nil || uuid.UUID(need.BoundMcpID.Bytes) != priorID {
					t.Fatalf("binding changed before callback: %+v err=%v", need, err)
				}
				provisional, err := q.GetMCPServerByID(t.Context(), pgUUID(started.ResourceID))
				if err != nil || provisional.Lifecycle != "provisional" || !provisional.ProvisionalNeedID.Valid {
					t.Fatalf("provisional MCP = %+v err=%v", provisional, err)
				}
				available, err := q.ListAvailableMCPServers(t.Context(), []pgtype.UUID{pgUUID(f.principal.UserID)})
				if err != nil {
					t.Fatal(err)
				}
				for _, item := range available {
					if item.ID == provisional.ID {
						t.Fatal("provisional MCP leaked into inventory")
					}
				}
				if mode == "oauth_discovery" && f.registrations != 1 {
					t.Fatalf("DCR registrations = %d, want 1", f.registrations)
				}
				state, err := q.GetOAuthStateForResource(t.Context(), pgUUID(started.ResourceID))
				if err != nil {
					t.Fatal(err)
				}
				switch outcome {
				case "success":
					if _, err := f.service.OAuthCallback(t.Context(), "code", state.State, "", ""); err != nil {
						t.Fatal(err)
					}
					active, err := q.GetMCPServerByID(t.Context(), pgUUID(started.ResourceID))
					if err != nil || active.Lifecycle != "active" || active.ProvisionalNeedID.Valid || active.GrantedScopes != "read write" || !active.ScopesVerified {
						t.Fatalf("active MCP = %+v err=%v", active, err)
					}
					need, _ = q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "mcp_server", Slug: f.targetSlug})
					if uuid.UUID(need.BoundMcpID.Bytes) != started.ResourceID {
						t.Fatalf("success binding = %+v", need)
					}
				case "denial":
					if _, err := f.service.OAuthCallback(t.Context(), "", state.State, "access_denied", "denied"); err != nil {
						t.Fatal(err)
					}
				case "partial grant":
					scope := "read"
					f.tokenScope = &scope
					if _, err := f.service.OAuthCallback(t.Context(), "code", state.State, "", ""); err != nil {
						t.Fatal(err)
					}
				}
				if outcome != "success" {
					if _, err := q.GetMCPServerByID(t.Context(), pgUUID(started.ResourceID)); !errors.Is(err, pgx.ErrNoRows) {
						t.Fatalf("failed provisional remains: %v", err)
					}
					need, _ = q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(f.agentID), Type: "mcp_server", Slug: f.targetSlug})
					if uuid.UUID(need.BoundMcpID.Bytes) != priorID {
						t.Fatalf("failure changed prior binding: %+v", need)
					}
					priorAfter, err := q.GetMCPServerByID(t.Context(), prior.ID)
					if err != nil || priorAfter.AccessTokenRef != priorAccess || priorAfter.GrantedScopes != "read" {
						t.Fatalf("failure changed prior MCP: %+v err=%v", priorAfter, err)
					}
				}
			})
		}
	}
}
