package apitest_test

import (
	"context"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
)

// TestLLMUsage_SurvivesAgentDeletion: the spend ledger is durable. A usage row
// snapshots the agent slug/name + user email at write time, and after the agent
// is deleted the row survives with agent_id nulled but the identity retained.
func TestLLMUsage_SurvivesAgentDeletion(t *testing.T) {
	h := apitest.Setup(t)
	ctx := context.Background()
	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner, Slug: "ledger-agent", Name: "Ledger Agent"})
	q := dbq.New(h.DB.Pool())

	if err := q.InsertLLMUsage(ctx, dbq.InsertLLMUsageParams{
		AgentID:           pgUUID(agentID),
		UserID:            pgUUID(owner),
		ProviderCatalogID: "openai", Model: "gpt-5", Capability: "text", CallKind: "chat", Slug: "default",
		TokensIn: 100, TokensOut: 50, TokensCached: 10, TokensReasoning: 0,
		Units: 0, UnitKind: "token",
		CostInput: 0.001, CostOutput: 0.002, CostTotal: 0.003,
		FinishReason: "stop", Errored: false, LatencyMs: 1200,
	}); err != nil {
		t.Fatalf("insert usage: %v", err)
	}

	// Identity was snapshotted at write.
	var slug, name, email string
	if err := h.DB.Pool().QueryRow(ctx,
		`SELECT agent_slug, agent_name, user_email FROM llm_usage WHERE agent_id=$1`, pgUUID(agentID),
	).Scan(&slug, &name, &email); err != nil {
		t.Fatalf("read usage: %v", err)
	}
	if slug != "ledger-agent" || name != "Ledger Agent" || email == "" {
		t.Fatalf("denormalized identity not captured: slug=%q name=%q email=%q", slug, name, email)
	}

	// Delete the agent via its principal (the real deletion path; agents.id
	// cascades from principals, and llm_usage.agent_id is ON DELETE SET NULL).
	if _, err := h.DB.Pool().Exec(ctx, `DELETE FROM principals WHERE id=$1`, pgUUID(agentID)); err != nil {
		t.Fatalf("delete agent principal: %v", err)
	}

	var count int
	var allNull bool
	if err := h.DB.Pool().QueryRow(ctx,
		`SELECT count(*), bool_and(agent_id IS NULL) FROM llm_usage WHERE agent_slug='ledger-agent'`,
	).Scan(&count, &allNull); err != nil {
		t.Fatalf("read after delete: %v", err)
	}
	if count != 1 {
		t.Fatalf("ledger row should survive agent deletion, got count=%d", count)
	}
	if !allNull {
		t.Error("agent_id should be NULL after agent deletion (ON DELETE SET NULL)")
	}
}
