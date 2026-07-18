package api

import (
	"context"
	"testing"

	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
)

func TestRewrapDatabaseRotatesSecrets(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	agentID, _ := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	oldKey := make([]byte, 32)
	newKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i], newKey[i] = 1, 2
	}
	ref := "agent/" + agentID.String() + "/git_webhook_secret"
	oldStore := secrets.NewLocal(crypto.New(oldKey))
	stored, err := oldStore.Put(ctx, ref, "webhook-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.ConnectAgentGit(ctx, dbq.ConnectAgentGitParams{
		ID:               toPgUUID(agentID),
		GitRemoteUrl:     "https://example.test/repo.git",
		GitDefaultBranch: "main",
		GitWebhookSecret: stored,
		GitMode:          "read_only",
	}); err != nil {
		t.Fatal(err)
	}
	store := secrets.NewLocal(crypto.New(newKey, oldKey))
	type result struct {
		changed int64
		err     error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			changed, err := secrets.RewrapDatabase(ctx, testDB.Pool(), store)
			results <- result{changed: changed, err: err}
		}()
	}
	close(start)
	var changed int64
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("RewrapDatabase: %v", result.err)
		}
		changed += result.changed
	}
	if changed != 1 {
		t.Fatalf("concurrent changed total = %d, want 1", changed)
	}
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		t.Fatal(err)
	}
	if agent.GitWebhookSecret == stored {
		t.Fatal("git webhook secret was not re-encrypted")
	}
	plain, err := store.Get(ctx, ref, agent.GitWebhookSecret)
	if err != nil || plain != "webhook-secret" {
		t.Fatalf("decrypted = %q, %v", plain, err)
	}
	if _, err := oldStore.Get(ctx, ref, agent.GitWebhookSecret); err == nil {
		t.Fatal("rotated secret remains decryptable by the old key")
	}
	changed, err = secrets.RewrapDatabase(ctx, testDB.Pool(), store)
	if err != nil || changed != 0 {
		t.Fatalf("second RewrapDatabase = %d, %v", changed, err)
	}
}

func TestRewrapDatabaseRollsBackOnInvalidEnvelope(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	agentID, _ := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	oldKey := make([]byte, 32)
	newKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i], newKey[i] = 1, 2
	}
	ref := "agent/" + agentID.String() + "/git_webhook_secret"
	stored, err := secrets.NewLocal(crypto.New(oldKey)).Put(ctx, ref, "webhook-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.ConnectAgentGit(ctx, dbq.ConnectAgentGitParams{
		ID:               toPgUUID(agentID),
		GitRemoteUrl:     "https://example.test/repo.git",
		GitDefaultBranch: "main",
		GitWebhookSecret: stored,
		GitMode:          "read_only",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Pool().Exec(ctx, `UPDATE agents SET db_password = 'generic-plaintext' WHERE id = $1`, toPgUUID(agentID)); err != nil {
		t.Fatal(err)
	}

	if _, err := secrets.RewrapDatabase(ctx, testDB.Pool(), secrets.NewLocal(crypto.New(newKey, oldKey))); err == nil {
		t.Fatal("RewrapDatabase accepted an invalid envelope")
	}
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		t.Fatal(err)
	}
	if agent.GitWebhookSecret != stored {
		t.Fatalf("git webhook secret changed after rollback: %q", agent.GitWebhookSecret)
	}
	if agent.DbPassword != "generic-plaintext" {
		t.Fatalf("generic plaintext changed after rollback: %q", agent.DbPassword)
	}
}

func TestCreateAgentDefaultsPublicRoutesOff(t *testing.T) {
	skipIfNoDB(t)
	agentID, _ := testAgentAndUser(t)
	agent, err := dbq.New(testDB.Pool()).GetAgentByID(context.Background(), toPgUUID(agentID))
	if err != nil {
		t.Fatal(err)
	}
	if agent.AllowPublicRoutes {
		t.Fatal("new agent allows public routes")
	}
}
