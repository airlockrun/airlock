package trigger

import (
	"context"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func TestAgentStartWelcomeIncludesWebAppURL(t *testing.T) {
	skipIfNoTriggerDB(t)
	ctx := context.Background()
	q := dbq.New(triggerTestDB.Pool())
	suffix := uuid.NewString()[:8]
	owner, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "start-" + suffix + "@example.com",
		DisplayName: "Start Owner",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	agent, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name:             "Welcome Agent",
		Slug:             "welcome-" + suffix,
		OwnerPrincipalID: owner.ID,
		Config:           []byte("{}"),
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	conv := NewAgentSlashConv(
		q,
		nil,
		zap.NewNop(),
		uuid.UUID(agent.ID.Bytes),
		func(slug string) string { return "https://" + slug + ".agents.example" },
	)
	wantURL := "https://" + agent.Slug + ".agents.example/"
	for _, message := range []string{"/start", "/start payload", "/start@welcome_bot", "/START@Welcome_Bot payload"} {
		t.Run(message, func(t *testing.T) {
			result, err := TrySlashCommand(ctx, conv, pgtype.UUID{}, agentsdk.AccessPublic, message)
			if err != nil {
				t.Fatalf("TrySlashCommand: %v", err)
			}
			if !result.Handled {
				t.Fatal("start command was not handled")
			}
			if !strings.Contains(result.Reply, "Welcome Agent") {
				t.Errorf("reply = %q, want agent name", result.Reply)
			}
			if !strings.Contains(result.Reply, wantURL) {
				t.Errorf("reply = %q, want URL %q", result.Reply, wantURL)
			}
		})
	}
}
