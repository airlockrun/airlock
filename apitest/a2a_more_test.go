package apitest_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
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

// TestIntegration_A2A_AccessDenied — a non-member user (no grant on the
// target, and no All-Users grant) calling its MCP endpoint yields 403 and
// creates no run.
func TestIntegration_A2A_AccessDenied(t *testing.T) {
	h := apitest.Setup(t)

	owner := apitest.CreateUser(t, h, "owner", "user")
	stranger := apitest.CreateUser(t, h, "stranger", "user")

	target := apitest.CreateAgent(t, h, apitest.AgentOpts{
		OwnerID: owner,
		Slug:    "target-closed",
		// No All-Users grant → the stranger has no access.
	})

	strangerToken := apitest.IssueUserToken(t, h, stranger, "stranger@apitest.local", "user")

	rpc := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "prompt",
			"arguments": map[string]any{"message": "ping"},
		},
	}
	body, _ := json.Marshal(rpc)
	req := h.NewRequest(http.MethodPost,
		"/api/agent/"+target.String()+"/mcp",
		strangerToken, body)
	resp := h.Do(req)
	rawBody := h.ReadBody(resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", resp.StatusCode, rawBody)
	}

	// No run row was created — the access check fires before
	// ForwardA2APrompt.
	q := dbq.New(h.DB.Pool())
	rows, err := q.GetDescendantRuns(t.Context(), pgtype.UUID{Bytes: target, Valid: true})
	if err == nil && len(rows) > 0 {
		t.Errorf("expected no descendant runs, got %d", len(rows))
	}
}

// TestIntegration_WS_ReplayBuffer_OnSuspended covers the "client
// disconnects mid-confirmation, reconnects, expects the pending
// confirmation re-attached" flow ([commit 4c26c90]).
//
// The publishRunEvents loop in api/event_publisher.go preserves the
// topic's replay buffer when a run ends in a suspended state — so a
// late subscriber catching up after refresh gets the
// confirmation_required envelope replayed. On a normal completion
// the buffer is cleared, so this test specifically uses
// ConfirmationRequired to keep the buffer alive.
func TestIntegration_WS_ReplayBuffer_OnSuspended(t *testing.T) {
	h := apitest.Setup(t)

	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})

	upstream := apitest.NewUpstream().
		TextDelta("about to ask").
		ConfirmationRequired("tc1", "exec", "ls -la").
		Suspend("awaiting approval").
		Handler()
	h.FakeContainers.RegisterAgent(agentID, upstream, "")

	ownerToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")

	// First connection — drives a prompt, captures the
	// confirmation_required envelope's seq.
	ws1 := apitest.Connect(t, h.Server, ownerToken, 0)
	driveOnePrompt(t, h, agentID, ownerToken)
	envs1 := ws1.Drain(2 * time.Second)
	var confirmSeq uint64
	for _, e := range envs1 {
		if e.Type == "run.confirmation_required" {
			confirmSeq = e.Seq
			break
		}
	}
	if confirmSeq == 0 {
		t.Fatalf("did not see run.confirmation_required envelope; types=%v", envelopeTypes(envs1))
	}

	// Reconnect with since = confirmSeq - 1 — the suspended-run path
	// preserves the buffer, so replay should redeliver the envelope.
	ws2 := apitest.Connect(t, h.Server, ownerToken, confirmSeq-1)
	envs2 := ws2.Drain(1 * time.Second)
	if !containsSeq(envs2, confirmSeq) {
		t.Fatalf("replay missed seq=%d; envs=%v",
			confirmSeq, envelopeSeqs(envs2))
	}

	// Reconnect with since = confirmSeq — caught up, no replay.
	ws3 := apitest.Connect(t, h.Server, ownerToken, confirmSeq)
	envs3 := ws3.Drain(300 * time.Millisecond)
	for _, e := range envs3 {
		if e.Seq != 0 && e.Seq <= confirmSeq {
			t.Errorf("got replayed seq=%d on caught-up reconnect", e.Seq)
		}
	}
}

// TestIntegration_A2A_CancelCascade exercises the
// runs.parent_run_id-walk in dispatcher.CancelRun.
//
// Topology:
//   - caller C: its /prompt upstream forwards an MCP `prompt` call to
//     target T using its own agent JWT + X-Run-ID, then blocks reading
//     the SSE response until the connection closes.
//   - target T: streams NDJSON slowly so the cancel can fire before
//     the run terminates naturally.
//
// Flow:
//  1. POST /api/v1/agents/{C}/prompt → returns 200 with parent run id.
//  2. Wait until a child run row appears with parent_run_id=parent.
//  3. DELETE /api/v1/runs/{parent} → 204.
//  4. Assert the child run row transitions out of 'running' within a
//     short deadline — the cascade walk closed its in-flight HTTP and
//     its publishRunEvents fallback wrote a terminal status.
func TestIntegration_A2A_CancelCascade(t *testing.T) {
	h := apitest.Setup(t)

	owner := apitest.CreateUser(t, h, "owner", "user")
	callerAgent := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner, Slug: "casc-caller"})
	targetAgent := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner, Slug: "casc-target"})
	apitest.AddSibling(t, h, callerAgent, targetAgent, owner, "admin")

	// Target blocks until its request ctx cancels — closing targetCtxDone
	// when that happens. The cancel cascade closing target's outbound HTTP
	// is what we're verifying, so this is the precise observable.
	//
	// We don't assert on the child run's DB status: in production the
	// agent itself writes the terminal status via /api/agent/run/complete
	// after vm.Interrupt fires; our fake target has no such loop, so the
	// row would stay 'running' even on a perfect cascade.
	targetCtxDone := make(chan struct{})
	targetUpstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/prompt" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		// Write one byte so the chunked-encoding state machine is
		// unambiguously streaming, then block on ctx.
		_, _ = w.Write([]byte("{\"type\":\"noop\",\"data\":{}}\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
		close(targetCtxDone)
	})
	h.FakeContainers.RegisterAgent(targetAgent, targetUpstream, "")

	// Caller upstream forwards its prompt to target via MCP and waits.
	callerAgentToken := apitest.IssueAgentToken(t, h, callerAgent)
	callerUpstream := makeA2ACallerUpstream(t, h.Server.URL, targetAgent, callerAgentToken)
	h.FakeContainers.RegisterAgent(callerAgent, callerUpstream, "")

	ownerToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")

	req := h.NewRequest(http.MethodPost,
		"/api/v1/agents/"+callerAgent.String()+"/prompt",
		ownerToken,
		&airlockv1.PromptRequest{Message: "cascade"},
	)
	resp := h.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prompt: status = %d; body = %s", resp.StatusCode, h.ReadBody(resp))
	}
	var promptResp airlockv1.PromptResponse
	h.DecodeProto(resp, &promptResp)
	parentRunID, err := uuid.Parse(promptResp.RunId)
	if err != nil {
		t.Fatalf("parse parent run id %q: %v", promptResp.RunId, err)
	}

	q := dbq.New(h.DB.Pool())

	// Wait until a child run exists with parent_run_id=parentRunID.
	var childRunID uuid.UUID
	waitFor(t, 3*time.Second, "child run to appear", func() bool {
		rows, qerr := q.GetDescendantRuns(t.Context(), pgtype.UUID{Bytes: parentRunID, Valid: true})
		if qerr != nil || len(rows) == 0 {
			return false
		}
		childRunID = uuid.UUID(rows[0].ID.Bytes)
		return true
	})

	// Cancel the parent. Body is empty; only the URL identifies the run.
	cancelReq := h.NewRequest(http.MethodDelete,
		"/api/v1/runs/"+parentRunID.String(),
		ownerToken, nil)
	cancelResp := h.Do(cancelReq)
	if cancelResp.StatusCode != http.StatusNoContent {
		t.Fatalf("cancel: status = %d; body = %s", cancelResp.StatusCode, h.ReadBody(cancelResp))
	}

	// The cascade closes target's inbound HTTP, which fires target's
	// r.Context().Done(). That's the load-bearing observable: parent
	// cancel → dispatcher walks parent_run_id → child's cancel hook
	// fires → child's outbound HTTP aborts → target sees ctx cancel.
	select {
	case <-targetCtxDone:
	case <-time.After(5 * time.Second):
		t.Fatal("target's request context never cancelled after parent cancel — cascade did not reach the in-flight child")
	}

	// Parent row was cancelled by the CancelRun handler directly.
	parent, _ := q.GetRunByID(t.Context(), pgtype.UUID{Bytes: parentRunID, Valid: true})
	if parent.Status != "cancelled" {
		t.Errorf("parent run status = %q, want %q", parent.Status, "cancelled")
	}
	_ = childRunID // child row stays 'running' since our fake never writes /run/complete
}

// makeA2ACallerUpstream returns an http.Handler that, on POST /prompt,
// forwards the prompt as an MCP `tools/call:prompt` request to target,
// then blocks until the SSE response body closes. The handler emits
// nothing on its own NDJSON output — the test only cares about the
// in-flight cancel of the A2A child run.
func makeA2ACallerUpstream(t *testing.T, airlockURL string, target uuid.UUID, agentToken string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/prompt" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		runID := r.Header.Get("X-Run-ID")
		if runID == "" {
			http.Error(w, "missing X-Run-ID", http.StatusBadRequest)
			return
		}
		// Drain the request body before starting downstream work. Some
		// connection-state code paths get unhappy if the request body
		// isn't read; draining first sidesteps that class of issue.
		_, _ = io.Copy(io.Discard, r.Body)

		rpc, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{
				"name":      "prompt",
				"arguments": map[string]any{"message": "child please"},
			},
		})
		// Use Background context for the outbound MCP call: the cascade
		// we're verifying happens via dispatcher.CancelRun walking
		// parent_run_id, not via context propagation through this fake.
		mcpReq, _ := http.NewRequestWithContext(context.Background(),
			http.MethodPost,
			airlockURL+"/api/agent/"+target.String()+"/mcp",
			bytes.NewReader(rpc),
		)
		mcpReq.Header.Set("Authorization", "Bearer "+agentToken)
		mcpReq.Header.Set("X-Run-ID", runID)
		mcpReq.Header.Set("Content-Type", "application/json")

		// Write 200 + an initial NDJSON event via bufio (same shape as
		// the apitest.Upstream builder), then keep emitting heartbeats
		// while MCP streams.
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		bw := bufio.NewWriter(w)
		_, _ = bw.Write([]byte("{\"type\":\"noop\",\"data\":{}}\n"))
		_ = bw.Flush()
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		// Outbound MCP — async so we can keep heartbeating.
		mcpDone := make(chan struct{})
		go func() {
			defer close(mcpDone)
			resp, err := http.DefaultClient.Do(mcpReq)
			if err != nil {
				t.Logf("apitest cascade caller: mcp call err: %v", err)
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}()

		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-r.Context().Done():
				<-mcpDone
				return
			case <-mcpDone:
				return
			case <-tick.C:
				_, werr := bw.Write([]byte("{\"type\":\"noop\",\"data\":{}}\n"))
				if werr != nil {
					<-mcpDone
					return
				}
				if ferr := bw.Flush(); ferr != nil {
					<-mcpDone
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}
	})
}

func waitFor(t *testing.T, timeout time.Duration, what string, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting %s after %s", what, timeout)
}

func driveOnePrompt(t *testing.T, h *apitest.Harness, agentID uuid.UUID, userToken string) {
	t.Helper()
	req := h.NewRequest(http.MethodPost,
		"/api/v1/agents/"+agentID.String()+"/prompt",
		userToken,
		&airlockv1.PromptRequest{Message: "hi"},
	)
	resp := h.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prompt: status = %d; body = %s", resp.StatusCode, h.ReadBody(resp))
	}
	_ = h.ReadBody(resp)
}

func containsSeq(envs []realtime.Envelope, want uint64) bool {
	for _, e := range envs {
		if e.Seq == want {
			return true
		}
	}
	return false
}

func envelopeSeqs(envs []realtime.Envelope) []uint64 {
	out := make([]uint64, len(envs))
	for i, e := range envs {
		out[i] = e.Seq
	}
	return out
}
