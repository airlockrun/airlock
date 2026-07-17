package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type proxyContainerManager struct {
	container *container.Container
}

func (m *proxyContainerManager) StartAgent(context.Context, container.AgentOpts) (*container.Container, error) {
	return m.container, nil
}

func (m *proxyContainerManager) GetRunning(context.Context, uuid.UUID) (*container.Container, error) {
	return m.container, nil
}

func (m *proxyContainerManager) RunningAgents(context.Context, []uuid.UUID) (map[uuid.UUID]bool, error) {
	return nil, nil
}

func (m *proxyContainerManager) StopAgent(context.Context, uuid.UUID) error { return nil }
func (m *proxyContainerManager) MarkBusy(uuid.UUID)                         {}
func (m *proxyContainerManager) MarkIdle(uuid.UUID)                         {}

func (m *proxyContainerManager) StartToolserver(context.Context, container.ToolserverOpts) (*container.Container, error) {
	return nil, nil
}

func (m *proxyContainerManager) StopToolserver(context.Context, string) error { return nil }
func (m *proxyContainerManager) KillToolserver(context.Context, string) error { return nil }
func (m *proxyContainerManager) CaptureToolserverDiagnostics(context.Context, string, string) error {
	return nil
}
func (m *proxyContainerManager) RemoveImage(context.Context, string) error { return nil }
func (m *proxyContainerManager) LockSwap(uuid.UUID) func()                 { return func() {} }

func TestSubdomainProxyForwardsAuthoritativeCallerHeaders(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	agentID, ownerID := testAgentAndUser(t)
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}

	enc := testEncryptor()
	dbPassword, err := enc.Put(ctx, "agent/"+agentID.String()+"/db_password", "test-password")
	if err != nil {
		t.Fatalf("encrypt DB password: %v", err)
	}
	if err := q.UpdateAgentDBPassword(ctx, dbq.UpdateAgentDBPasswordParams{ID: agent.ID, DbPassword: dbPassword}); err != nil {
		t.Fatalf("UpdateAgentDBPassword: %v", err)
	}
	if err := q.UpdateAgentRefs(ctx, dbq.UpdateAgentRefsParams{ID: agent.ID, SourceRef: "test-source", ImageRef: "test-image"}); err != nil {
		t.Fatalf("UpdateAgentRefs: %v", err)
	}
	if err := q.UpdateAgentA2ASettings(ctx, dbq.UpdateAgentA2ASettingsParams{
		ID: agent.ID, AllowPublicRoutes: true,
	}); err != nil {
		t.Fatalf("UpdateAgentA2ASettings: %v", err)
	}

	member, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "proxy-member@example.com",
		DisplayName: "Proxy Member",
		TenantRole:  "admin",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{AgentID: agent.ID, GranteeID: member.ID, Role: "user"}); err != nil {
		t.Fatalf("UpsertAgentGrant: %v", err)
	}

	for path, access := range map[string]string{
		"/public":        "public",
		"/static/{name}": "public",
		"/user":          "user",
		"/admin":         "admin",
	} {
		if err := q.UpsertRoute(ctx, dbq.UpsertRouteParams{
			AgentID: agent.ID, Path: path, Method: http.MethodGet, Access: access, Description: "test route",
		}); err != nil {
			t.Fatalf("UpsertRoute(%s): %v", path, err)
		}
	}
	if err := q.UpsertRoute(ctx, dbq.UpsertRouteParams{
		AgentID: agent.ID, Path: "/user", Method: http.MethodPost, Access: "user", Description: "test mutation",
	}); err != nil {
		t.Fatalf("UpsertRoute(POST /user): %v", err)
	}

	requests := make(chan *http.Request, 6)
	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		http.SetCookie(w, &http.Cookie{Name: relayCookieName, Value: "collision", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: relayNonceName, Value: "collision", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: relayDevNonceName, Value: "collision", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: accessCookieName, Value: "collision", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: refreshCookieName, Value: "collision", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "agent_cookie", Value: "preserved", Path: "/"})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer agentServer.Close()

	containers := &proxyContainerManager{container: &container.Container{
		Endpoint: agentServer.URL,
		Token:    "container-token",
	}}
	dispatcher := trigger.NewDispatcher(&config.Config{
		JWTSecret: testJWTSecret,
		DBPort:    "5432",
		DBName:    "airlock",
		DBSSLMode: "disable",
	}, testDB, containers, enc, zap.NewNop())
	handler := SubdomainProxy(
		"agents.test", testDB, nil, dispatcher, &trigger.BridgeManager{},
		testJWTSecret, "https://airlock.test", http.NotFoundHandler(),
	)

	owner, err := q.GetUserByID(ctx, toPgUUID(ownerID))
	if err != nil {
		t.Fatalf("GetUserByID(owner): %v", err)
	}
	issueToken := func(t *testing.T, user dbq.User) string {
		t.Helper()
		now := time.Now()
		session, err := q.CreateUserSession(ctx, dbq.CreateUserSessionParams{
			UserID:           user.ID,
			Kind:             "web",
			ClientName:       "proxy test",
			DeviceName:       "proxy test",
			RefreshTokenHash: []byte(uuid.NewString()),
			AuthenticatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
			ExpiresAt:        pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true},
		})
		if err != nil {
			t.Fatalf("CreateUserSession: %v", err)
		}
		token, err := auth.IssueUserAccessToken(testJWTSecret, pgUUID(user.ID), user.Email, user.DisplayName, user.TenantRole, user.MustChangePassword, pgUUID(session.ID), user.AuthEpoch, now)
		if err != nil {
			t.Fatalf("IssueUserAccessToken: %v", err)
		}
		return token
	}
	ownerToken := issueToken(t, owner)
	memberToken := issueToken(t, member)
	issueSubdomainToken := func(t *testing.T, user dbq.User, accessToken string) string {
		t.Helper()
		claims, err := auth.ValidateUserAccessToken(testJWTSecret, accessToken)
		if err != nil {
			t.Fatalf("ValidateUserAccessToken: %v", err)
		}
		token, err := auth.IssueSubdomainToken(
			testJWTSecret, agentID, pgUUID(user.ID), uuid.MustParse(claims.SessionID),
			user.Email, user.DisplayName, user.TenantRole, user.AuthEpoch,
		)
		if err != nil {
			t.Fatalf("IssueSubdomainToken: %v", err)
		}
		return token
	}
	ownerSubdomainToken := issueSubdomainToken(t, owner, ownerToken)
	memberSubdomainToken := issueSubdomainToken(t, member, memberToken)
	unrelated, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "proxy-unrelated@example.com",
		DisplayName: "Proxy Unrelated",
		TenantRole:  "admin",
	})
	if err != nil {
		t.Fatalf("CreateUser(unrelated): %v", err)
	}
	unrelatedSubdomainToken := issueSubdomainToken(t, unrelated, issueToken(t, unrelated))

	tests := []struct {
		name     string
		path     string
		token    string
		access   string
		userID   string
		email    string
		userName string
	}{
		{name: "public route", path: "/public", access: "public"},
		{name: "public static route", path: "/static/app.css", access: "public"},
		{name: "authenticated public route retains effective access", path: "/public", token: ownerToken, access: "admin", userID: ownerID.String(), email: owner.Email, userName: owner.DisplayName},
		{name: "public asset", path: "/__air/assets/htmx.min.js", access: "public"},
		{name: "user route gets effective admin access", path: "/user", token: ownerToken, access: "admin", userID: ownerID.String(), email: owner.Email, userName: owner.DisplayName},
		{name: "tenant admin gets agent user access", path: "/user", token: memberToken, access: "user", userID: pgUUID(member.ID).String(), email: member.Email, userName: member.DisplayName},
		{name: "admin route", path: "/admin", token: ownerToken, access: "admin", userID: ownerID.String(), email: owner.Email, userName: owner.DisplayName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+agent.Slug+".agents.test"+tt.path, nil)
			req.Host = agent.Slug + ".agents.test"
			req.Header.Set("Connection", "X-Caller-Access, X-User-ID, X-User-Email, X-User-Name")
			req.Header.Set("X-Caller-Access", "admin")
			req.Header.Set("X-User-ID", uuid.NewString())
			req.Header.Set("X-User-Email", "spoof@example.com")
			req.Header.Set("X-User-Name", "Spoofed")
			req.Header.Set("Cookie", relayCookieName+"=secret; "+relayNonceName+"=nonce; "+relayDevNonceName+"=devnonce; "+accessCookieName+"=platform; "+refreshCookieName+"=refresh; agent_cookie=request-value")
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
			}
			forwarded := <-requests
			for header, want := range map[string]string{
				"X-Caller-Access": tt.access,
				"X-User-ID":       tt.userID,
				"X-User-Email":    tt.email,
				"X-User-Name":     tt.userName,
				"Authorization":   "Bearer container-token",
			} {
				if got := forwarded.Header.Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
			if got := forwarded.Header.Get("Cookie"); got != "agent_cookie=request-value" {
				t.Errorf("Cookie = %q, want agent-owned cookie only", got)
			}
			setCookies := rec.Header().Values("Set-Cookie")
			if len(setCookies) != 1 || !strings.HasPrefix(setCookies[0], "agent_cookie=preserved") {
				t.Errorf("Set-Cookie = %v, want agent-owned cookie only", setCookies)
			}
		})
	}

	for _, tt := range []struct {
		name   string
		origin string
		bearer bool
		want   int
	}{
		{name: "cookie exact origin", origin: "http://" + agent.Slug + ".agents.test", want: http.StatusNoContent},
		{name: "cookie missing origin", want: http.StatusForbidden},
		{name: "cookie sibling origin", origin: "http://sibling.agents.test", want: http.StatusForbidden},
		{name: "user bearer is exempt", bearer: true, want: http.StatusNoContent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://"+agent.Slug+".agents.test/user", nil)
			req.Host = agent.Slug + ".agents.test"
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.bearer {
				req.Header.Set("Authorization", "Bearer "+ownerToken)
			} else {
				req.AddCookie(&http.Cookie{Name: relayCookieName, Value: ownerSubdomainToken})
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == http.StatusNoContent {
				<-requests
			} else {
				select {
				case <-requests:
					t.Fatal("rejected request reached agent")
				default:
				}
			}
		})
	}

	if err := q.UpdateAgentA2ASettings(ctx, dbq.UpdateAgentA2ASettingsParams{ID: agent.ID}); err != nil {
		t.Fatalf("disable public routes: %v", err)
	}
	for _, tt := range []struct {
		name       string
		path       string
		token      string
		wantStatus int
		wantAccess string
	}{
		{name: "member public route", path: "/public", token: memberSubdomainToken, wantStatus: http.StatusNoContent, wantAccess: "user"},
		{name: "member static asset", path: "/static/app.css", token: memberSubdomainToken, wantStatus: http.StatusNoContent, wantAccess: "user"},
		{name: "owner framework asset", path: "/__air/assets/htmx.min.js", token: ownerSubdomainToken, wantStatus: http.StatusNoContent, wantAccess: "admin"},
		{name: "anonymous static asset", path: "/static/app.css", wantStatus: http.StatusUnauthorized},
		{name: "anonymous framework asset", path: "/__air/assets/htmx.min.js", wantStatus: http.StatusUnauthorized},
		{name: "authenticated non-member static asset", path: "/static/app.css", token: unrelatedSubdomainToken, wantStatus: http.StatusUnauthorized},
	} {
		t.Run("public routes disabled/"+tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+agent.Slug+".agents.test"+tt.path, nil)
			req.Host = agent.Slug + ".agents.test"
			if strings.HasPrefix(tt.path, "/static/") {
				req.Header.Set("Accept", "text/css,*/*;q=0.1")
			}
			if tt.token != "" {
				req.AddCookie(&http.Cookie{Name: relayCookieName, Value: tt.token})
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus == http.StatusNoContent {
				forwarded := <-requests
				if got := forwarded.Header.Get("X-Caller-Access"); got != tt.wantAccess {
					t.Fatalf("X-Caller-Access = %q, want %q", got, tt.wantAccess)
				}
				return
			}
			select {
			case <-requests:
				t.Fatal("rejected request reached agent")
			default:
			}
		})
	}
}

func TestMatchRouteUsesServeMuxGrammar(t *testing.T) {
	routes := []dbq.AgentRoute{
		{Method: http.MethodGet, Path: "/files/{path...}", Access: "user"},
		{Method: http.MethodGet, Path: "/files/{name}", Access: "admin"},
		{Method: http.MethodGet, Path: "/files/static", Access: "admin"},
		{Method: http.MethodPost, Path: "/files/{path...}", Access: "public"},
	}
	for _, tc := range []struct {
		name   string
		method string
		path   string
		access string
	}{
		{name: "literal precedence", method: http.MethodGet, path: "/files/static", access: "admin"},
		{name: "multi wildcard", method: http.MethodGet, path: "/files/a/b", access: "user"},
		{name: "method", method: http.MethodPost, path: "/files/a", access: "public"},
		{name: "head uses get", method: http.MethodHead, path: "/files/a/b", access: "user"},
		{name: "escaped slash stays in segment", method: http.MethodGet, path: "/files/a%2Fb", access: "admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://agent.test"+tc.path, nil)
			route, ok, err := matchRoute(routes, req)
			if err != nil || !ok || route.Access != tc.access {
				t.Fatalf("matchRoute = (%q, %v, %v), want access %q", route.Access, ok, err, tc.access)
			}
		})
	}
}

func TestMatchRouteRejectsAmbiguousPatterns(t *testing.T) {
	routes := []dbq.AgentRoute{
		{Method: http.MethodGet, Path: "/users/{id}"},
		{Method: http.MethodGet, Path: "/users/{name}"},
	}
	req := httptest.NewRequest(http.MethodGet, "http://agent.test/users/42", nil)
	if _, _, err := matchRoute(routes, req); err == nil {
		t.Fatal("matchRoute accepted ambiguous patterns")
	}
}

func TestValidateSubdomainAuthSeparatesBearerAndCookieProfiles(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	otherAgentID := uuid.New()
	now := time.Now()
	session, err := dbq.New(testDB.Pool()).CreateUserSession(context.Background(), dbq.CreateUserSessionParams{
		UserID:           toPgUUID(userID),
		Kind:             "web",
		ClientName:       "test",
		DeviceName:       "test",
		RefreshTokenHash: []byte(uuid.NewString()),
		AuthenticatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
		ExpiresAt:        pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	userToken, _ := auth.IssueUserAccessToken(testJWTSecret, userID, "user@example.com", "User", "user", false, pgUUID(session.ID), 0, now)
	oauthToken, _ := auth.IssueOAuthAccessToken(testJWTSecret, userID, "user@example.com", "user", "client", "mcp", "https://example.test/mcp", 0)
	agentToken, _ := auth.IssueAgentToken(testJWTSecret, agentID, 1)
	subdomainToken, _ := auth.IssueSubdomainToken(testJWTSecret, agentID, userID, pgUUID(session.ID), "user@example.com", "User", "user", 0)
	forcedUserToken, _ := auth.IssueUserAccessToken(testJWTSecret, userID, "user@example.com", "User", "user", true, pgUUID(session.ID), 0, now)
	q := dbq.New(testDB.Pool())

	for name, tc := range map[string]struct {
		bearer string
		cookie string
		target uuid.UUID
		want   bool
	}{
		"user bearer":                  {bearer: userToken, target: agentID, want: true},
		"OAuth bearer":                 {bearer: oauthToken, target: agentID},
		"agent bearer":                 {bearer: agentToken, target: agentID},
		"subdomain bearer":             {bearer: subdomainToken, target: agentID},
		"target subdomain cookie":      {cookie: subdomainToken, target: agentID, want: true},
		"wrong subdomain cookie":       {cookie: subdomainToken, target: otherAgentID},
		"user token cookie":            {cookie: userToken, target: agentID},
		"OAuth token cookie":           {cookie: oauthToken, target: agentID},
		"agent token cookie":           {cookie: agentToken, target: agentID},
		"stale forced user bearer":     {bearer: forcedUserToken, target: agentID, want: true},
		"invalid bearer blocks cookie": {bearer: oauthToken, cookie: subdomainToken, target: agentID},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://agent.example.test/", nil)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: relayCookieName, Value: tc.cookie})
			}
			_, ok, _ := validateSubdomainAuth(req, q, testJWTSecret, tc.target)
			if ok != tc.want {
				t.Errorf("validateSubdomainAuth() = %v, want %v", ok, tc.want)
			}
		})
	}

	if rows, err := q.RevokeUserSessionByID(context.Background(), dbq.RevokeUserSessionByIDParams{ID: session.ID, UserID: toPgUUID(userID)}); err != nil || rows != 1 {
		t.Fatalf("RevokeUserSessionByID = (%d, %v)", rows, err)
	}
	revokedCookieReq := httptest.NewRequest(http.MethodGet, "https://agent.example.test/", nil)
	revokedCookieReq.AddCookie(&http.Cookie{Name: relayCookieName, Value: subdomainToken})
	if _, ok, _ := validateSubdomainAuth(revokedCookieReq, q, testJWTSecret, agentID); ok {
		t.Fatal("subdomain cookie remained valid after per-session revoke")
	}

	if _, err := q.AdvanceUserAuthEpochAndRevokeSessions(context.Background(), dbq.AdvanceUserAuthEpochAndRevokeSessionsParams{
		ID: toPgUUID(userID),
	}); err != nil {
		t.Fatalf("AdvanceUserAuthEpochAndRevokeSessions: %v", err)
	}
	for name, tc := range map[string]struct {
		bearer string
		cookie string
	}{
		"revoked user bearer":      {bearer: userToken},
		"revoked subdomain cookie": {cookie: subdomainToken},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://agent.example.test/", nil)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: relayCookieName, Value: tc.cookie})
			}
			if _, ok, _ := validateSubdomainAuth(req, q, testJWTSecret, agentID); ok {
				t.Fatal("revoked authentication was accepted")
			}
		})
	}
}

func TestAgentSlugFromHost(t *testing.T) {
	for name, tc := range map[string]struct {
		host string
		want string
		ok   bool
	}{
		"exact subdomain":  {host: "demo.agents.test", want: "demo", ok: true},
		"port":             {host: "demo.agents.test:8443", want: "demo", ok: true},
		"case":             {host: "Demo.Agents.Test", want: "demo", ok: true},
		"nested label":     {host: "evil.demo.agents.test"},
		"suffix confusion": {host: "demo.agents.test.evil"},
		"reserved":         {host: "api.agents.test"},
		"bare domain":      {host: "agents.test"},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := agentSlugFromHost(tc.host, "agents.test")
			if got != tc.want || ok != tc.ok {
				t.Errorf("agentSlugFromHost(%q) = (%q, %v), want (%q, %v)", tc.host, got, ok, tc.want, tc.ok)
			}
		})
	}
}
