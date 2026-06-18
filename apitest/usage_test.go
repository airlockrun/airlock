package apitest_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

// TestUsage_AdminRollupAndGating: the Usage endpoint is admin-only and rolls up
// the ledger into a summary + per-agent breakdown.
func TestUsage_AdminRollupAndGating(t *testing.T) {
	h := apitest.Setup(t)
	ctx := context.Background()
	admin := apitest.CreateUser(t, h, "admin", "admin")
	adminTok := apitest.IssueUserToken(t, h, admin, "admin@apitest.local", "admin")
	plain := apitest.CreateUser(t, h, "plain", "user")
	plainTok := apitest.IssueUserToken(t, h, plain, "plain@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: admin, Slug: "usage-agent", Name: "Usage Agent"})

	if err := dbq.New(h.DB.Pool()).InsertLLMUsage(ctx, dbq.InsertLLMUsageParams{
		AgentID: pgUUID(agentID), UserID: pgUUID(admin),
		ProviderCatalogID: "openai", Model: "gpt-5", Capability: "text", CallKind: "chat", Slug: "default",
		TokensIn: 100, TokensOut: 50, TokensCached: 10, TokensReasoning: 0,
		Units: 0, UnitKind: "token", CostInput: 0.01, CostOutput: 0.02, CostTotal: 0.03,
		FinishReason: "stop", Errored: false, LatencyMs: 100,
	}); err != nil {
		t.Fatalf("insert usage: %v", err)
	}

	// Non-admin is denied.
	if code := h.Do(h.NewRequest(http.MethodGet, "/api/v1/usage", plainTok, nil)).StatusCode; code != http.StatusForbidden {
		t.Fatalf("non-admin usage: want 403, got %d", code)
	}

	// Admin gets the rollup.
	resp := h.Do(h.NewRequest(http.MethodGet, "/api/v1/usage?days=30", adminTok, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin usage: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	out := &airlockv1.GetUsageResponse{}
	h.DecodeProto(resp, out)
	if out.Summary == nil || out.Summary.Calls != 1 || out.Summary.CostTotal == 0 {
		t.Fatalf("unexpected summary: %+v", out.Summary)
	}
	found := false
	for _, a := range out.ByAgent {
		if a.AgentSlug == "usage-agent" && a.Calls == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("by-agent rollup missing usage-agent: %+v", out.ByAgent)
	}
}
