package apitest_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
)

func allowedModels(t *testing.T, h *apitest.Harness, token string) *airlockv1.ListAllowedModelsResponse {
	t.Helper()
	resp := h.Do(h.NewRequest(http.MethodGet, "/api/v1/models/allowed", token, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed models: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	out := &airlockv1.ListAllowedModelsResponse{}
	h.DecodeProto(resp, out)
	return out
}

// TestAllowedModels_AdminRestrictedToGranted: a tenant admin is held to the
// allow-list too — empty before any grant, and after allowing a model (granted
// to the All-Users group, which is in the admin's grantee set) it appears.
func TestAllowedModels_AdminRestrictedToGranted(t *testing.T) {
	h := apitest.Setup(t)
	admin := apitest.CreateUser(t, h, "admin", "admin")
	tok := apitest.IssueUserToken(t, h, admin, "admin@apitest.local", "admin")

	if resp := allowedModels(t, h, tok); resp.Unrestricted || len(resp.Models) != 0 {
		t.Fatalf("admin pre-grant: want restricted+empty, got unrestricted=%v n=%d", resp.Unrestricted, len(resp.Models))
	}

	ctx := context.Background()
	q := dbq.New(h.DB.Pool())
	provID := uuid.New()
	if _, err := q.CreateProvider(ctx, dbq.CreateProviderParams{
		ID: pgUUID(provID), CatalogID: "openai", Slug: "test", DisplayName: "Test", ApiKey: "k", BaseUrl: "", IsEnabled: true,
	}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := q.CreateModelGrant(ctx, dbq.CreateModelGrantParams{
		CatalogID: pgUUID(provID), Model: "gpt-5", GranteeID: pgUUID(authz.GroupUser),
	}); err != nil {
		t.Fatalf("seed model grant: %v", err)
	}

	resp := allowedModels(t, h, tok)
	if resp.Unrestricted {
		t.Error("admin should be restricted")
	}
	if len(resp.Models) != 1 || resp.Models[0].Model != "gpt-5" {
		t.Fatalf("want 1 allowed model gpt-5, got %d", len(resp.Models))
	}
}

// TestAllowedModels_UserSeesGrants: a non-admin gets exactly the models granted
// to a principal in their grantee set (the user group in OSS) — deny-by-default
// before any grant, then the granted pair after.
func TestAllowedModels_UserSeesGrants(t *testing.T) {
	h := apitest.Setup(t)
	user := apitest.CreateUser(t, h, "user", "user")
	tok := apitest.IssueUserToken(t, h, user, "user@apitest.local", "user")

	if resp := allowedModels(t, h, tok); resp.Unrestricted || len(resp.Models) != 0 {
		t.Fatalf("ungranted user: want restricted+empty, got unrestricted=%v n=%d", resp.Unrestricted, len(resp.Models))
	}

	ctx := context.Background()
	q := dbq.New(h.DB.Pool())
	provID := uuid.New()
	if _, err := q.CreateProvider(ctx, dbq.CreateProviderParams{
		ID: pgUUID(provID), CatalogID: "openai", Slug: "test", DisplayName: "Test", ApiKey: "k", BaseUrl: "", IsEnabled: true,
	}); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if _, err := q.CreateModelGrant(ctx, dbq.CreateModelGrantParams{
		CatalogID: pgUUID(provID), Model: "gpt-5", GranteeID: pgUUID(authz.GroupUser),
	}); err != nil {
		t.Fatalf("seed model grant: %v", err)
	}

	resp := allowedModels(t, h, tok)
	if resp.Unrestricted {
		t.Error("user should be restricted")
	}
	if len(resp.Models) != 1 {
		t.Fatalf("want 1 allowed model, got %d", len(resp.Models))
	}
	if resp.Models[0].ProviderId != provID.String() || resp.Models[0].Model != "gpt-5" {
		t.Errorf("unexpected allowed model: provider=%q model=%q", resp.Models[0].ProviderId, resp.Models[0].Model)
	}
}
