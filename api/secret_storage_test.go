package api

import (
	"context"
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
)

func TestRewrapDatabaseEncryptsGitWebhookSecret(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	agentID, _ := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	if err := q.ConnectAgentGit(ctx, dbq.ConnectAgentGitParams{
		ID:               toPgUUID(agentID),
		GitRemoteUrl:     "https://example.test/repo.git",
		GitDefaultBranch: "main",
		GitWebhookSecret: "plain-secret",
		GitMode:          "read_only",
	}); err != nil {
		t.Fatal(err)
	}
	store := testEncryptor()
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
	if !secrets.IsEnvelope(agent.GitWebhookSecret) {
		t.Fatalf("git webhook secret is not enveloped: %q", agent.GitWebhookSecret)
	}
	plain, err := store.Get(ctx, "agent/"+agentID.String()+"/git_webhook_secret", agent.GitWebhookSecret)
	if err != nil || plain != "plain-secret" {
		t.Fatalf("decrypted = %q, %v", plain, err)
	}
	changed, err = secrets.RewrapDatabase(ctx, testDB.Pool(), store)
	if err != nil || changed != 0 {
		t.Fatalf("second RewrapDatabase = %d, %v", changed, err)
	}
}

func TestRewrapDatabaseRollsBackOnGenericPlaintext(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	agentID, _ := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	if err := q.ConnectAgentGit(ctx, dbq.ConnectAgentGitParams{
		ID:               toPgUUID(agentID),
		GitRemoteUrl:     "https://example.test/repo.git",
		GitDefaultBranch: "main",
		GitWebhookSecret: "plain-git-secret",
		GitMode:          "read_only",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Pool().Exec(ctx, `UPDATE agents SET db_password = 'generic-plaintext' WHERE id = $1`, toPgUUID(agentID)); err != nil {
		t.Fatal(err)
	}

	if _, err := secrets.RewrapDatabase(ctx, testDB.Pool(), testEncryptor()); err == nil {
		t.Fatal("RewrapDatabase accepted generic plaintext")
	}
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		t.Fatal(err)
	}
	if agent.GitWebhookSecret != "plain-git-secret" {
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
