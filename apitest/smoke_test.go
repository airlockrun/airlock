package apitest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestIntegration_Smoke_PromptFlow drives the full prompt path:
//
//   - real router (middleware chain, auth, route resolution).
//   - real dispatcher, dialing a FakeContainerManager-backed
//     httptest.Server that streams canned NDJSON.
//   - real publishRunEvents → real pubsub → real WS hub.
//   - test WS client subscribed via Hub.Subscribe (auto-subscribed at
//     /ws upgrade time).
//
// Asserts: 200 with run_id, run row in DB, two text-delta envelopes on
// the WS, dispatcher correctly bracketed the call (busy == idle == 1).
func TestIntegration_Smoke_PromptFlow(t *testing.T) {
	h := apitest.Setup(t)

	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})

	upstream := apitest.NewUpstream().
		TextDelta("Hello ").
		TextDelta("world").
		Finish().
		Handler()
	h.FakeContainers.RegisterAgent(agentID, upstream, "")

	ownerToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")

	ws := apitest.Connect(t, h.Server, ownerToken, 0)

	req := h.NewRequest(http.MethodPost,
		"/api/v1/agents/"+agentID.String()+"/prompt",
		ownerToken,
		&airlockv1.PromptRequest{Message: "hi"},
	)
	resp := h.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prompt: status = %d; body = %s", resp.StatusCode, h.ReadBody(resp))
	}
	var promptResp airlockv1.PromptResponse
	h.DecodeProto(resp, &promptResp)
	if promptResp.RunId == "" {
		t.Fatal("prompt: empty run_id")
	}
	runID, err := uuid.Parse(promptResp.RunId)
	if err != nil {
		t.Fatalf("prompt: invalid run_id %q: %v", promptResp.RunId, err)
	}

	// Drain a window then filter. Two text-delta payloads expected.
	envs := ws.Drain(2 * time.Second)
	var deltas int
	for _, e := range envs {
		if e.Type == "run.text_delta" {
			deltas++
		}
	}
	if deltas < 2 {
		t.Fatalf("expected >=2 text_delta envelopes, got %d (types: %v)", deltas, envelopeTypes(envs))
	}

	// Run row exists and points at the right agent.
	q := dbq.New(h.DB.Pool())
	run, err := q.GetRunByID(context.Background(), pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		t.Fatalf("GetRunByID: %v", err)
	}
	if got := uuid.UUID(run.AgentID.Bytes); got != agentID {
		t.Errorf("run.agent_id = %s, want %s", got, agentID)
	}

	// Idle-reaper bracketing — every busy paired with one idle.
	if got, want := h.FakeContainers.BusyCount(agentID), 1; got != want {
		t.Errorf("BusyCount = %d, want %d", got, want)
	}
	if got, want := h.FakeContainers.IdleCount(agentID), 1; got != want {
		t.Errorf("IdleCount = %d, want %d", got, want)
	}
}

func envelopeTypes(envs []realtime.Envelope) []string {
	out := make([]string, len(envs))
	for i, e := range envs {
		out[i] = e.Type
	}
	return out
}
