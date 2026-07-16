package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
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
		"/public": "public",
		"/user":   "user",
		"/admin":  "admin",
	} {
		if err := q.UpsertRoute(ctx, dbq.UpsertRouteParams{
			AgentID: agent.ID, Path: path, Method: http.MethodGet, Access: access, Description: "test route",
		}); err != nil {
			t.Fatalf("UpsertRoute(%s): %v", path, err)
		}
	}

	requests := make(chan *http.Request, 6)
	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
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

	ownerToken, err := auth.IssueToken(testJWTSecret, ownerID, "owner@example.com", "Owner", "user", false)
	if err != nil {
		t.Fatalf("IssueToken(owner): %v", err)
	}
	memberToken, err := auth.IssueToken(testJWTSecret, pgUUID(member.ID), member.Email, "", "admin", false)
	if err != nil {
		t.Fatalf("IssueToken(member): %v", err)
	}

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
		{name: "authenticated public route retains effective access", path: "/public", token: ownerToken, access: "admin", userID: ownerID.String(), email: "owner@example.com", userName: "Owner"},
		{name: "public asset", path: "/__air/assets/htmx.min.js", access: "public"},
		{name: "user route gets effective admin access", path: "/user", token: ownerToken, access: "admin", userID: ownerID.String(), email: "owner@example.com", userName: "Owner"},
		{name: "tenant admin gets agent user access", path: "/user", token: memberToken, access: "user", userID: pgUUID(member.ID).String(), email: member.Email},
		{name: "admin route", path: "/admin", token: ownerToken, access: "admin", userID: ownerID.String(), email: "owner@example.com", userName: "Owner"},
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
		})
	}
}
