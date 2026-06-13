package apitest_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestIntegration_StoppedAgent_Surfaces asserts that prompting a stopped
// agent yields a clean, surface-appropriate signal rather than a 500.
func TestIntegration_StoppedAgent_Surfaces(t *testing.T) {
	h := apitest.Setup(t)

	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{
		OwnerID: owner,
		Slug:    "stopped-one",
		Stopped: true,
	})
	ownerToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")
	q := dbq.New(h.DB.Pool())

	t.Run("web prompt returns 409, no run", func(t *testing.T) {
		req := h.NewRequest(http.MethodPost,
			"/api/v1/agents/"+agentID.String()+"/prompt",
			ownerToken,
			&airlockv1.PromptRequest{Message: "hi"},
		)
		resp := h.Do(req)
		body := h.ReadBody(resp)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body = %s", resp.StatusCode, body)
		}
		if !strings.Contains(strings.ToLower(string(body)), "stopped") {
			t.Errorf("body should mention stopped; got %s", body)
		}
		// A 409 short-circuits before any run row is created.
		runs, err := q.ListRunsByAgent(t.Context(), dbq.ListRunsByAgentParams{
			AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
			Lim:     10,
		})
		if err != nil {
			t.Fatalf("ListRunsByAgent: %v", err)
		}
		if len(runs) != 0 {
			t.Errorf("expected 0 runs for stopped agent, got %d", len(runs))
		}
	})

	t.Run("A2A prompt returns JSON-RPC error naming the target", func(t *testing.T) {
		caller := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner, Slug: "stopped-caller"})
		// Parent conversation + run so the agent JWT principal resolves.
		conv, err := q.CreateWebConversation(t.Context(), dbq.CreateWebConversationParams{
			AgentID: pgtype.UUID{Bytes: caller, Valid: true},
			UserID:  pgtype.UUID{Bytes: owner, Valid: true},
			Title:   "p",
		})
		if err != nil {
			t.Fatalf("CreateWebConversation: %v", err)
		}
		parentRun, err := q.CreateRun(t.Context(), dbq.CreateRunParams{
			AgentID:      pgtype.UUID{Bytes: caller, Valid: true},
			InputPayload: []byte(`{}`),
			TriggerType:  "prompt",
			TriggerRef:   uuid.UUID(conv.ID.Bytes).String(),
		})
		if err != nil {
			t.Fatalf("CreateRun: %v", err)
		}

		callerToken := apitest.IssueAgentToken(t, h, caller)
		rpc, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{
				"name":      "prompt",
				"arguments": map[string]any{"message": "ping"},
			},
		})
		req := h.NewRequest(http.MethodPost,
			"/api/agent/"+agentID.String()+"/mcp", callerToken, rpc)
		req.Header.Set("X-Run-ID", uuid.UUID(parentRun.ID.Bytes).String())
		resp := h.Do(req)
		body := h.ReadBody(resp)
		// MCP errors ride on a 200 with a JSON-RPC error envelope.
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body)
		}
		var env struct {
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("decode JSON-RPC: %v; body=%s", err, body)
		}
		if env.Error == nil {
			t.Fatalf("expected JSON-RPC error, got %s", body)
		}
		if !strings.Contains(env.Error.Message, "stopped") || !strings.Contains(env.Error.Message, "stopped-one") {
			t.Errorf("error message should name the stopped target; got %q", env.Error.Message)
		}
	})

	t.Run("webhook returns 409", func(t *testing.T) {
		// Register a no-verify webhook on the stopped agent.
		if err := q.UpsertWebhook(t.Context(), dbq.UpsertWebhookParams{
			AgentID:    pgtype.UUID{Bytes: agentID, Valid: true},
			Path:       "wh",
			VerifyMode: "none",
		}); err != nil {
			t.Fatalf("UpsertWebhook: %v", err)
		}
		req := h.NewRequest(http.MethodPost,
			"/webhooks/"+agentID.String()+"/wh", "", []byte(`{}`))
		resp := h.Do(req)
		body := h.ReadBody(resp)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body = %s", resp.StatusCode, body)
		}
	})
}
