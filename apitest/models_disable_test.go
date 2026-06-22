package apitest_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

// seedGrantedModel creates an enabled provider and grants (provider, model) to
// the All-Users group, returning the provider id and grant id.
func seedGrantedModel(t *testing.T, h *apitest.Harness, model string) (provID, grantID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	q := dbq.New(h.DB.Pool())
	provID = uuid.New()
	if _, err := q.CreateProvider(ctx, dbq.CreateProviderParams{
		ID: pgUUID(provID), CatalogID: "openai", Slug: "test-" + model, DisplayName: "Test", ApiKey: "k", BaseUrl: "", IsEnabled: true,
	}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	g, err := q.CreateModelGrant(ctx, dbq.CreateModelGrantParams{
		CatalogID: pgUUID(provID), Model: model, GranteeID: pgUUID(authz.GroupUser),
	})
	if err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return provID, uuid.UUID(g.ID.Bytes)
}

func setAgentExec(t *testing.T, h *apitest.Harness, agentID, provID uuid.UUID, model string) {
	t.Helper()
	if _, err := h.DB.Pool().Exec(context.Background(),
		`UPDATE agents SET exec_provider_id=$1, exec_model=$2 WHERE id=$3`,
		pgUUID(provID), model, pgUUID(agentID)); err != nil {
		t.Fatalf("set agent exec override: %v", err)
	}
}

func agentExecModel(t *testing.T, h *apitest.Harness, agentID uuid.UUID) string {
	t.Helper()
	var model string
	if err := h.DB.Pool().QueryRow(context.Background(),
		`SELECT exec_model FROM agents WHERE id=$1`, pgUUID(agentID)).Scan(&model); err != nil {
		t.Fatalf("read agent exec model: %v", err)
	}
	return model
}

// TestRevokeModelGrant_ResetsAgentOverrides: disabling (revoking) a model that
// an agent pins as an override resets that agent back to the workspace default.
func TestRevokeModelGrant_ResetsAgentOverrides(t *testing.T) {
	h := apitest.Setup(t)
	admin := apitest.CreateUser(t, h, "admin", "admin")
	tok := apitest.IssueUserToken(t, h, admin, "admin@apitest.local", "admin")

	provID, grantID := seedGrantedModel(t, h, "custom-exec")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: admin, Slug: "pins-model"})
	setAgentExec(t, h, agentID, provID, "custom-exec")

	resp := h.Do(h.NewRequest(http.MethodDelete, "/api/v1/model-grants/"+grantID.String(), tok, nil))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	if got := agentExecModel(t, h, agentID); got != "" {
		t.Errorf("exec override = %q, want '' (reset to default)", got)
	}
}

// TestRevokeModelGrant_LeavesSystemDefault: revoking a model that is also a
// configured system default leaves agent overrides untouched (it stays usable).
func TestRevokeModelGrant_LeavesSystemDefault(t *testing.T) {
	h := apitest.Setup(t)
	admin := apitest.CreateUser(t, h, "admin", "admin")
	tok := apitest.IssueUserToken(t, h, admin, "admin@apitest.local", "admin")

	provID, grantID := seedGrantedModel(t, h, "default-exec")
	// Make it the system default exec model.
	if _, err := h.DB.Pool().Exec(context.Background(),
		`UPDATE system_settings SET default_exec_provider_id=$1, default_exec_model=$2`,
		pgUUID(provID), "default-exec"); err != nil {
		t.Fatalf("set system default: %v", err)
	}
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: admin, Slug: "pins-default"})
	setAgentExec(t, h, agentID, provID, "default-exec")

	resp := h.Do(h.NewRequest(http.MethodDelete, "/api/v1/model-grants/"+grantID.String(), tok, nil))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	if got := agentExecModel(t, h, agentID); got != "default-exec" {
		t.Errorf("exec override = %q, want 'default-exec' (left untouched — still a default)", got)
	}
}
