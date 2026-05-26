package apitest_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestIntegration_A2A_HappyPath exercises the full sibling-agent path:
//
//  1. User U is admin member of caller agent A and target agent T.
//  2. A's run is mid-flight (conversation + run row inserted directly).
//  3. A's "code" calls POST /api/agent/{T}/mcp using agent JWT +
//     X-Run-ID, asking the prompt tool with a message.
//  4. T's upstream streams a couple of text-deltas + finish.
//  5. SSE response on the MCP socket carries notifications/progress
//     events, then a final result envelope.
//
// Asserts:
//   - HTTP 200 with text/event-stream.
//   - >=2 progress notifications received.
//   - A child run row exists with parent_run_id=A's run, trigger_type='a2a'.
//   - U's WS subscription on A's topic surfaces the child events tagged
//     with SubagentInfo.
func TestIntegration_A2A_HappyPath(t *testing.T) {
	h := apitest.Setup(t)

	owner := apitest.CreateUser(t, h, "owner", "user")
	callerAgent := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner, Slug: "caller"})
	targetAgent := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner, Slug: "target"})

	// Target upstream — streams a small canned NDJSON sequence.
	targetUpstream := apitest.NewUpstream().
		TextDelta("a2a hello").
		Finish().
		Handler()
	h.FakeContainers.RegisterAgent(targetAgent, targetUpstream, "")

	// Caller agent is registered too (its container would also be reached
	// when the dispatcher records the parent run's bus events). The
	// caller never actually receives a request in this test.
	h.FakeContainers.RegisterAgent(callerAgent, apitest.NewUpstream().Finish().Handler(), "")

	ctx := context.Background()
	q := dbq.New(h.DB.Pool())

	// Parent conversation + run on the caller agent — what an in-flight
	// run on A looks like at the moment its code makes an A2A call.
	parentConv, err := q.CreateWebConversation(ctx, dbq.CreateWebConversationParams{
		AgentID: pgtype.UUID{Bytes: callerAgent, Valid: true},
		UserID:  pgtype.UUID{Bytes: owner, Valid: true},
		Title:   "parent",
	})
	if err != nil {
		t.Fatalf("CreateWebConversation: %v", err)
	}
	parentRun, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID:      pgtype.UUID{Bytes: callerAgent, Valid: true},
		InputPayload: []byte(`{}`),
		TriggerType:  "prompt",
		TriggerRef:   uuid.UUID(parentConv.ID.Bytes).String(),
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	parentRunID := uuid.UUID(parentRun.ID.Bytes)

	// User WS subscribes to A's topic (auto-subscribed at upgrade because
	// they're a member). The child run's events should mirror onto
	// A's topic with a Subagent tag.
	userToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")
	ws := apitest.Connect(t, h.Server, userToken, 0)

	// A's "agent code" calls the MCP prompt tool on T. Authorization is
	// the caller agent's JWT plus X-Run-ID pointing at the parent run.
	callerAgentToken := apitest.IssueAgentToken(t, h, callerAgent)
	rpcReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "prompt",
			"arguments": map[string]any{
				"message": "ping",
			},
		},
	}
	rpcBody, _ := json.Marshal(rpcReq)
	req := h.NewRequest(http.MethodPost,
		"/api/agent/"+targetAgent.String()+"/mcp",
		callerAgentToken,
		rpcBody,
	)
	req.Header.Set("X-Run-ID", parentRunID.String())
	resp := h.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mcp call: status = %d; body = %s", resp.StatusCode, h.ReadBody(resp))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("mcp call: content-type = %q, want text/event-stream", ct)
	}

	// Read the SSE stream until EOF; count notifications/progress and
	// capture the final result envelope.
	notifications, result := readSSEResponse(t, resp.Body)
	if len(notifications) < 1 {
		t.Errorf("expected >=1 notification, got %d", len(notifications))
	}
	if result == nil {
		t.Errorf("expected final SSE result envelope, got none")
	}

	// Child run row exists with the right parent + trigger.
	var childRun dbq.Run
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rows, qerr := q.GetDescendantRuns(ctx, pgtype.UUID{Bytes: parentRunID, Valid: true})
		if qerr == nil && len(rows) > 0 {
			r, gerr := q.GetRunByID(ctx, rows[0].ID)
			if gerr == nil {
				childRun = r
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if childRun.ID.Bytes == [16]byte{} {
		t.Fatal("expected child run row with parent_run_id=parentRunID, none appeared")
	}
	if got := uuid.UUID(childRun.AgentID.Bytes); got != targetAgent {
		t.Errorf("child run agent_id = %s, want %s", got, targetAgent)
	}
	if childRun.TriggerType != "a2a" {
		t.Errorf("child run trigger_type = %q, want %q", childRun.TriggerType, "a2a")
	}

	// WS should have at least one envelope tagged with Subagent.
	envs := ws.Drain(2 * time.Second)
	var taggedCount int
	for _, e := range envs {
		if e.Subagent != nil {
			taggedCount++
		}
	}
	if taggedCount == 0 {
		t.Errorf("expected at least one WS envelope tagged with SubagentInfo, got 0 (envs=%v)", envelopeTypes(envs))
	}
}

// readSSEResponse drains an SSE body, returning notifications and the
// final response envelope. The MCP socket emits each frame as a
// `data: {...}\n\n` block; we just scan for those and unmarshal.
func readSSEResponse(t *testing.T, body io.ReadCloser) (notifications []map[string]any, result map[string]any) {
	t.Helper()
	defer body.Close()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var env map[string]any
		if err := json.Unmarshal([]byte(payload), &env); err != nil {
			t.Logf("apitest: SSE decode: %v (raw=%s)", err, payload)
			continue
		}
		if _, hasID := env["id"]; hasID {
			result = env
			continue
		}
		notifications = append(notifications, env)
	}
	if err := sc.Err(); err != nil {
		t.Logf("apitest: SSE scan err: %v", err)
	}
	return notifications, result
}
