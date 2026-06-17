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

// TestAllowedModels_AdminUnrestricted: a tenant admin may assign any model.
func TestAllowedModels_AdminUnrestricted(t *testing.T) {
	h := apitest.Setup(t)
	admin := apitest.CreateUser(t, h, "admin", "admin")
	tok := apitest.IssueUserToken(t, h, admin, "admin@apitest.local", "admin")
	if resp := allowedModels(t, h, tok); !resp.Unrestricted {
		t.Error("admin should be unrestricted")
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
