package apitest_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestAgentTokenRevocationUsesLiveDatabaseVersion(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "token-owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	oldToken := apitest.IssueAgentToken(t, h, agentID)

	assertAgentAPIStatus(t, h, oldToken, http.StatusOK)
	q := dbq.New(h.DB.Pool())
	if _, err := q.IncrementAgentTokenVersion(context.Background(), pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		t.Fatalf("IncrementAgentTokenVersion: %v", err)
	}
	assertAgentAPIStatus(t, h, oldToken, http.StatusUnauthorized)
	assertAgentAPIStatus(t, h, apitest.IssueAgentToken(t, h, agentID), http.StatusOK)
}

func TestAgentTokenRejectedAfterStopAndDelete(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "lifecycle-owner", "user")
	q := dbq.New(h.DB.Pool())

	stoppedID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	stoppedToken := apitest.IssueAgentToken(t, h, stoppedID)
	if _, err := q.StopAgentAndRotateToken(context.Background(), dbq.StopAgentAndRotateTokenParams{
		ID: pgtype.UUID{Bytes: stoppedID, Valid: true},
	}); err != nil {
		t.Fatalf("StopAgentAndRotateToken: %v", err)
	}
	assertAgentAPIStatus(t, h, stoppedToken, http.StatusUnauthorized)

	deletedID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	deletedToken := apitest.IssueAgentToken(t, h, deletedID)
	if err := q.DeleteAgent(context.Background(), pgtype.UUID{Bytes: deletedID, Valid: true}); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	assertAgentAPIStatus(t, h, deletedToken, http.StatusUnauthorized)
}

func TestAgentTokenVersionIncrementsAreConcurrentSafe(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "concurrent-owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	const increments = 12

	var wg sync.WaitGroup
	errs := make(chan error, increments)
	for range increments {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := dbq.New(h.DB.Pool()).IncrementAgentTokenVersion(context.Background(), pgtype.UUID{Bytes: agentID, Valid: true})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent increment: %v", err)
		}
	}
	state, err := dbq.New(h.DB.Pool()).GetAgentTokenAuth(context.Background(), pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		t.Fatal(err)
	}
	if state.AgentTokenVersion != 1+increments {
		t.Fatalf("token version = %d, want %d", state.AgentTokenVersion, 1+increments)
	}
}

func assertAgentAPIStatus(t *testing.T, h *apitest.Harness, token string, want int) {
	t.Helper()
	resp := h.Do(h.NewRequest(http.MethodGet, "/api/agent/schedules", token, nil))
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("agent API status = %d, want %d", resp.StatusCode, want)
	}
}
