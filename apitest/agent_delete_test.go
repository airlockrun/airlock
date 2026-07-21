package apitest_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestIntegration_DeleteAgentRetriesFailedTeardown(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	token := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")
	path := "/api/v1/agents/" + agentID.String()

	h.FakeContainers.SetStopError(agentID, errors.New("network removal failed"))
	resp := h.Do(h.NewRequest(http.MethodDelete, path, token, nil))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("failed teardown status = %d, want 500; body = %s", resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()

	q := dbq.New(h.DB.Pool())
	if _, err := q.GetAgentByID(t.Context(), pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		t.Fatalf("agent row removed after failed teardown: %v", err)
	}

	h.FakeContainers.SetStopError(agentID, nil)
	resp = h.Do(h.NewRequest(http.MethodDelete, path, token, nil))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("retry status = %d, want 204; body = %s", resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()

	_, err := q.GetAgentByID(t.Context(), pgtype.UUID{Bytes: agentID, Valid: true})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetAgentByID after successful retry error = %v, want %v", err, pgx.ErrNoRows)
	}
}
