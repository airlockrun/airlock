package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/db/dbtest"
	"github.com/airlockrun/airlock/secrets"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	testDB    *db.DB
	testURL   string
	testReset func() error
)

func TestMain(m *testing.M) {
	url, reset, release, ok := dbtest.Setup(context.Background(), db.RunMigrations)
	if !ok {
		os.Exit(m.Run()) // no DB available; integration tests skip individually
	}
	testURL, testReset = url, reset
	testDB = db.New(context.Background(), url)
	code := m.Run()
	testDB.Close()
	release()
	os.Exit(code)
}

func skipIfNoDB(t *testing.T) {
	t.Helper()
	if testDB == nil {
		t.Skip("no test database (Docker unavailable)")
	}
	resetTestData(t)
}

// resetTestData restores the post-migration snapshot so each test starts
// from the exact migrated state — including migration-seeded singleton
// rows like system_settings — making the serial api suite (no
// t.Parallel) fully order-independent. Restore drops and recreates the
// database, so the shared testDB pool must be closed and rebuilt around
// it.
func resetTestData(t *testing.T) {
	t.Helper()
	testDB.Close()
	if err := testReset(); err != nil {
		t.Fatalf("resetTestData: restore snapshot: %v", err)
	}
	testDB = db.New(context.Background(), testURL)
}

const testJWTSecret = "test-secret-key-for-agent-api"

func testEncryptor() secrets.Store {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return secrets.NewLocal(crypto.New(key))
}

func testAgentHandler() *Handler {
	return &Handler{
		db:        testDB,
		encryptor: testEncryptor(),
		logger:    zap.NewNop(),
		// Mirrors config.Config.AgentBaseURL's shape. Required: the
		// prompt-data path (agent.go) calls this unconditionally and a
		// nil func field panics.
		agentBaseURL: func(slug string) string { return "http://" + slug + ".localhost" },
	}
}

// testRouter creates a chi router with AgentMiddleware and the given routes.
func testRouter(ah *Handler, setup func(r chi.Router)) http.Handler {
	r := chi.NewRouter()
	r.Use(auth.AgentMiddleware(testJWTSecret))
	setup(r)
	return r
}

func agentRequest(t *testing.T, method, path string, agentID uuid.UUID, body any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")

	token, err := auth.IssueAgentToken(testJWTSecret, agentID)
	if err != nil {
		t.Fatalf("IssueAgentToken: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// testAgentAndUser inserts a user and agent, returns both UUIDs.
func testAgentAndUser(t *testing.T) (agentID, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := dbq.New(testDB.Pool())

	suffix := uuid.New().String()[:8]
	user, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "test-" + suffix + "@example.com",
		DisplayName: "Test User",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	agent, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name:   "test-" + suffix,
		Slug:   "test-" + suffix,
		UserID: user.ID,
		Config: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Owner becomes agent admin — mirrors the Create handler.
	if err := q.AddAgentMember(ctx, dbq.AddAgentMemberParams{
		AgentID: agent.ID,
		UserID:  user.ID,
		Role:    "admin",
	}); err != nil {
		t.Fatalf("AddAgentMember: %v", err)
	}

	return pgUUID(agent.ID), pgUUID(user.ID)
}

// createTestAgent inserts a user and agent, returns the agent UUID.
func createTestAgent(t *testing.T) uuid.UUID {
	t.Helper()
	agentID, _ := testAgentAndUser(t)
	return agentID
}

// createTestBridge inserts a bridge, returns its UUID.
func createTestBridge(t *testing.T) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var bridgeID uuid.UUID
	err := testDB.Pool().QueryRow(ctx,
		`INSERT INTO bridges (type, name, bot_token_ref, bot_username, status, is_system, config, settings)
		 VALUES ('telegram', $1, '', '', 'active', false, '{}'::jsonb, '{}'::jsonb) RETURNING id`,
		"test-"+uuid.New().String()[:8],
	).Scan(&bridgeID)
	if err != nil {
		t.Fatalf("create bridge: %v", err)
	}
	return bridgeID
}

func TestUpsertConnection(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID := createTestAgent(t)

	def := agentsdk.ConnectionDef{
		Name:        "GitHub",
		Description: "GitHub API access",
		AuthMode:    agentsdk.ConnectionAuthOAuth,
		AuthURL:     "https://github.com/login/oauth/authorize",
		BaseURL:     "https://api.github.com",
		AuthInjection: agentsdk.AuthInjection{
			Type: "bearer",
		},
	}

	router := testRouter(ah, func(r chi.Router) {
		r.Put("/api/agent/connections/{slug}", ah.UpsertConnection)
	})

	req := agentRequest(t, "PUT", "/api/agent/connections/github", agentID, def)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d; body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Upsert again — should be idempotent.
	def.Description = "Updated description"
	req = agentRequest(t, "PUT", "/api/agent/connections/github", agentID, def)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("upsert again: status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestSync(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID := createTestAgent(t)

	syncReq := agentsdk.SyncRequest{
		Webhooks: []agentsdk.WebhookDef{
			{Path: "/webhook/github", Verify: "hmac", Header: "X-Hub-Signature-256"},
			{Path: "/webhook/stripe", Verify: "hmac", Header: "Stripe-Signature"},
		},
		Crons: []agentsdk.CronDef{
			{Name: "daily-digest", Schedule: "0 9 * * *"},
		},
	}

	router := testRouter(ah, func(r chi.Router) {
		r.Put("/api/agent/sync", ah.Sync)
	})

	req := agentRequest(t, "PUT", "/api/agent/sync", agentID, syncReq)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Sync again with fewer items — stale ones should be deleted.
	syncReq.Webhooks = []agentsdk.WebhookDef{
		{Path: "/webhook/github", Verify: "hmac", Header: "X-Hub-Signature-256"},
	}
	syncReq.Crons = nil

	req = agentRequest(t, "PUT", "/api/agent/sync", agentID, syncReq)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("sync again: status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Verify: only 1 webhook remains.
	q := dbq.New(testDB.Pool())
	webhooks, err := q.ListWebhooksByAgent(context.Background(), toPgUUID(agentID))
	if err != nil {
		t.Fatalf("ListWebhooksByAgent: %v", err)
	}
	if len(webhooks) != 1 {
		t.Errorf("webhooks count = %d, want 1", len(webhooks))
	}
}

func TestRunComplete(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID := createTestAgent(t)
	router := testRouter(ah, func(r chi.Router) {
		r.Post("/api/agent/run/complete", ah.RunComplete)
	})
	q := dbq.New(testDB.Pool())

	logs := []agentsdk.LogEntry{
		{Level: agentsdk.LogLevelInfo, Message: "line 1"},
		{Level: agentsdk.LogLevelWarn, Message: "line 2"},
	}

	check := func(status string) {
		runID := uuid.New()
		body := agentsdk.RunCompleteRequest{RunID: runID.String(), Status: status, Logs: logs}
		req := agentRequest(t, "POST", "/api/agent/run/complete", agentID, body)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %s: code = %d, want 200; body: %s", status, rec.Code, rec.Body.String())
		}
		run, err := q.GetRunByID(context.Background(), toPgUUID(runID))
		if err != nil {
			t.Fatalf("GetRunByID(%s): %v", status, err)
		}
		if run.Status != status {
			t.Errorf("status %s: run.Status = %q", status, run.Status)
		}
		// Logs are kept for every run, success and failure alike.
		if want := "line 1\n[warn] line 2"; run.StdoutLog != want {
			t.Errorf("status %s: StdoutLog = %q, want %q", status, run.StdoutLog, want)
		}
	}

	check("success")
	check("error")
}
