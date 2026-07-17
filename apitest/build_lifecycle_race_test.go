package apitest_test

import (
	"context"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestFinalAgentDeploymentCASInterleavings(t *testing.T) {
	tests := []struct {
		name           string
		initialStatus  string
		expectedStatus string
		nextStatus     string
		stopBefore     bool
		stopAfter      bool
		wantRows       int64
		wantStatus     string
		wantSourceRef  string
		wantImageRef   string
	}{
		{
			name:           "stop before token reservation rejects active upgrade",
			initialStatus:  "active",
			expectedStatus: "active",
			nextStatus:     "active",
			stopBefore:     true,
			wantStatus:     "stopped",
		},
		{
			name:           "stop after token reservation rejects active upgrade",
			initialStatus:  "active",
			expectedStatus: "active",
			nextStatus:     "active",
			stopAfter:      true,
			wantStatus:     "stopped",
		},
		{
			name:           "stop rejects initial activation",
			initialStatus:  "building",
			expectedStatus: "building",
			nextStatus:     "active",
			stopAfter:      true,
			wantStatus:     "stopped",
		},
		{
			name:           "stopped upgrade remains stopped",
			initialStatus:  "stopped",
			expectedStatus: "stopped",
			nextStatus:     "stopped",
			wantRows:       1,
			wantStatus:     "stopped",
			wantSourceRef:  "new-source",
			wantImageRef:   "agent:new",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := apitest.Setup(t)
			owner := apitest.CreateUser(t, h, "deployment-owner", "user")
			agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
			id := pgtype.UUID{Bytes: agentID, Valid: true}
			q := dbq.New(h.DB.Pool())
			if err := q.UpdateAgentStatus(context.Background(), dbq.UpdateAgentStatusParams{
				ID:     id,
				Status: tt.initialStatus,
			}); err != nil {
				t.Fatalf("set initial status: %v", err)
			}

			if tt.stopBefore {
				if _, err := q.StopAgentAndRotateToken(context.Background(), dbq.StopAgentAndRotateTokenParams{ID: id}); err != nil {
					t.Fatalf("stop before reservation: %v", err)
				}
			}
			version, err := q.IncrementAgentTokenVersion(context.Background(), id)
			if err != nil {
				t.Fatalf("reserve deployment token: %v", err)
			}
			if tt.stopAfter {
				if _, err := q.StopAgentAndRotateToken(context.Background(), dbq.StopAgentAndRotateTokenParams{ID: id}); err != nil {
					t.Fatalf("stop after reservation: %v", err)
				}
			}

			rows, err := q.FinalizeAgentDeployment(context.Background(), dbq.FinalizeAgentDeploymentParams{
				ID:                id,
				SourceRef:         "new-source",
				ImageRef:          "agent:new",
				NextStatus:        tt.nextStatus,
				AgentTokenVersion: version,
				ExpectedStatus:    tt.expectedStatus,
			})
			if err != nil {
				t.Fatalf("FinalizeAgentDeployment: %v", err)
			}
			if rows != tt.wantRows {
				t.Fatalf("rows = %d, want %d", rows, tt.wantRows)
			}
			agent, err := q.GetAgentByID(context.Background(), id)
			if err != nil {
				t.Fatalf("GetAgentByID: %v", err)
			}
			if agent.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", agent.Status, tt.wantStatus)
			}
			if agent.SourceRef != tt.wantSourceRef || agent.ImageRef != valueOr(tt.wantImageRef, "apitest:stub") {
				t.Fatalf("refs = (%q, %q), want (%q, %q)", agent.SourceRef, agent.ImageRef, tt.wantSourceRef, valueOr(tt.wantImageRef, "apitest:stub"))
			}
		})
	}
}

func TestInitialBuildLifecycleCASDoesNotOverwriteStop(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "initial-build-owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	id := pgtype.UUID{Bytes: agentID, Valid: true}
	q := dbq.New(h.DB.Pool())
	if err := q.UpdateAgentStatus(context.Background(), dbq.UpdateAgentStatusParams{ID: id, Status: "draft"}); err != nil {
		t.Fatal(err)
	}
	agent, err := q.GetAgentByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.StopAgentAndRotateToken(context.Background(), dbq.StopAgentAndRotateTokenParams{ID: id}); err != nil {
		t.Fatal(err)
	}

	rows, err := q.StartInitialAgentBuild(context.Background(), dbq.StartInitialAgentBuildParams{
		ID:                id,
		AgentTokenVersion: agent.AgentTokenVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("start rows = %d, want 0", rows)
	}
	rows, err = q.FailInitialAgentBuild(context.Background(), dbq.FailInitialAgentBuildParams{
		ID:                id,
		ErrorMessage:      "late build failure",
		AgentTokenVersion: agent.AgentTokenVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("failure rows = %d, want 0", rows)
	}
	stopped, err := q.GetAgentByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Status != "stopped" || stopped.ErrorMessage != "" {
		t.Fatalf("agent status/error = %q/%q, want stopped/empty", stopped.Status, stopped.ErrorMessage)
	}
}

func valueOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
