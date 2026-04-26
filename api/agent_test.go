package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var testDB *db.DB

func TestMain(m *testing.M) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		os.Exit(m.Run())
	}
	release, err := db.TestLockAndReset(url)
	if err != nil {
		log.Fatal(err)
	}
	testDB = db.New(context.Background(), url)
	code := m.Run()
	testDB.Close()
	release()
	os.Exit(code)
}

func skipIfNoDB(t *testing.T) {
	t.Helper()
	if testDB == nil {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}
}

const testJWTSecret = "test-secret-key-for-agent-api"

func testEncryptor() *crypto.Encryptor {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return crypto.New(key)
}

func testAgentHandler() *agentHandler {
	return &agentHandler{
		db:        testDB,
		encryptor: testEncryptor(),
		logger:    zap.NewNop(),
	}
}

// testRouter creates a chi router with AgentMiddleware and the given routes.
func testRouter(ah *agentHandler, setup func(r chi.Router)) http.Handler {
	r := chi.NewRouter()
	r.Use(auth.AgentMiddleware(testJWTSecret))
	setup(r)
	return r
}

func agentRequest(t *testing.T, method, path string, agentID uuid.UUID, body any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
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

	// Add creator as agent admin (matches Create handler behavior).
	_ = q.AddAgentMember(ctx, dbq.AddAgentMemberParams{
		AgentID: agent.ID,
		UserID:  user.ID,
		Role:    "admin",
	})

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
		`INSERT INTO bridges (type, name, token_encrypted, bot_username) VALUES ('telegram', $1, '', '') RETURNING id`,
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

	def := agentsdk.Connection{
		Name:        "GitHub",
		Description: "GitHub API access",
		AuthMode:    "oauth",
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
		Crons: []agentsdk.CronEntry{
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
	runID := uuid.New()

	body := agentsdk.RunCompleteRequest{
		RunID:  runID.String(),
		Status: "completed",
		Logs:   []string{"line 1", "line 2"},
	}

	router := testRouter(ah, func(r chi.Router) {
		r.Post("/api/agent/run/complete", ah.RunComplete)
	})

	req := agentRequest(t, "POST", "/api/agent/run/complete", agentID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Verify: run was recorded.
	q := dbq.New(testDB.Pool())
	run, err := q.GetRunByID(context.Background(), toPgUUID(runID))
	if err != nil {
		t.Fatalf("GetRunByID: %v", err)
	}
	if run.Status != "completed" {
		t.Errorf("run.Status = %q, want %q", run.Status, "completed")
	}
	if run.StdoutLog != "line 1\nline 2" {
		t.Errorf("run.StdoutLog = %q, want %q", run.StdoutLog, "line 1\nline 2")
	}
}

