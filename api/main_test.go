package api

import (
	"context"
	"os"
	"testing"

	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/db/dbtest"
	"github.com/airlockrun/airlock/secrets"
	"github.com/google/uuid"
)

// Per-package test bootstrap. Mirrors agentapi/agent_test.go's setup
// — both packages own their own TestMain so they can boot a fresh
// migrated DB independently, and both keep their fixture helpers
// (createTestAgent, etc.) scoped to in-package tests.

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

// resetTestData restores the post-migration snapshot so each test
// starts from the exact migrated state — including migration-seeded
// singleton rows like system_settings — making the serial api suite
// (no t.Parallel) fully order-independent.
func resetTestData(t *testing.T) {
	t.Helper()
	testDB.Close()
	if err := testReset(); err != nil {
		t.Fatalf("resetTestData: restore snapshot: %v", err)
	}
	testDB = db.New(context.Background(), testURL)
}

const testJWTSecret = "test-secret-key-for-api"

func testEncryptor() secrets.Store {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return secrets.NewLocal(crypto.New(key))
}

// createTestAgent inserts a user and agent (with the user as the
// agent's admin member), returns the agent UUID. Used by every
// operator-side test that needs a target agent.
func createTestAgent(t *testing.T) uuid.UUID {
	t.Helper()
	agentID, _ := testAgentAndUser(t)
	return agentID
}

// testAgentAndUser inserts a user and agent, returns both UUIDs.
// Owner becomes agent admin — mirrors the Create handler.
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
		Name:             "test-" + suffix,
		Slug:             "test-" + suffix,
		OwnerPrincipalID: user.ID,
		Config:           []byte("{}"),
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	if err := q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{
		AgentID:   agent.ID,
		GranteeID: user.ID,
		Role:      "admin",
	}); err != nil {
		t.Fatalf("UpsertAgentGrant: %v", err)
	}

	return pgUUID(agent.ID), pgUUID(user.ID)
}

// testConversation creates a web conversation under the given
// (agent, user), returning its UUID.
func testConversation(t *testing.T, agentID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	q := dbq.New(testDB.Pool())

	conv, err := q.CreateWebConversation(ctx, dbq.CreateWebConversationParams{
		AgentID: toPgUUID(agentID),
		UserID:  toPgUUID(userID),
		Title:   "test",
	})
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	return pgUUID(conv.ID)
}
