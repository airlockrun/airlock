package apitest_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	servicemodels "github.com/airlockrun/airlock/service/models"
	"github.com/google/uuid"
)

func createProvider(t *testing.T, h *apitest.Harness, token string, req *airlockv1.CreateProviderRequest, wantStatus int) *airlockv1.Provider {
	t.Helper()
	resp := h.Do(h.NewRequest(http.MethodPost, "/api/v1/providers/", token, req))
	if resp.StatusCode != wantStatus {
		t.Fatalf("create provider: status %d, want %d, body %s", resp.StatusCode, wantStatus, h.ReadBody(resp))
	}
	if wantStatus < 200 || wantStatus >= 300 {
		h.ReadBody(resp)
		return nil
	}
	out := &airlockv1.CreateProviderResponse{}
	h.DecodeProto(resp, out)
	return out.Provider
}

func replaceProviderModels(t *testing.T, h *apitest.Harness, token, providerID string, models ...*airlockv1.ProviderModel) {
	t.Helper()
	resp := h.Do(h.NewRequest(http.MethodPut, "/api/v1/providers/"+providerID+"/models", token, &airlockv1.ReplaceProviderModelsRequest{Models: models}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replace provider models: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
}

func TestProviders_MultipleRowsValidationAndConflicts(t *testing.T) {
	h := apitest.Setup(t)
	admin := apitest.CreateUser(t, h, "provider-admin", "admin")
	token := apitest.IssueUserToken(t, h, admin, "provider-admin@apitest.local", "admin")

	first := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai", Slug: "team-one", DisplayName: "Team One", ApiKey: "sk-one",
	}, http.StatusCreated)
	second := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai", Slug: "team-two", DisplayName: "Team Two", ApiKey: "sk-two",
	}, http.StatusCreated)
	if first.Id == second.Id || first.ProviderId != second.ProviderId {
		t.Fatalf("same-kind rows were not distinct: first=%+v second=%+v", first, second)
	}

	createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai", Slug: "team-one", DisplayName: "Duplicate", ApiKey: "sk-three",
	}, http.StatusConflict)
	createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai", Slug: "Not_Kebab", DisplayName: "Invalid", ApiKey: "sk-three",
	}, http.StatusBadRequest)
	createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai", Slug: "missing-key", DisplayName: "Missing Key",
	}, http.StatusBadRequest)
	createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "missing-url", DisplayName: "Missing URL",
	}, http.StatusBadRequest)
	createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "bad-url", DisplayName: "Bad URL", BaseUrl: "localhost:8080/v1",
	}, http.StatusBadRequest)
	local := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "local-no-auth", DisplayName: "Local", BaseUrl: "http://localhost:8080/v1",
	}, http.StatusCreated)
	if local.HasApiKey {
		t.Fatal("no-auth openai-compatible provider reports an API key")
	}
	row, err := dbq.New(h.DB.Pool()).GetProviderByID(context.Background(), pgUUID(uuid.MustParse(local.Id)))
	if err != nil {
		t.Fatalf("get local provider: %v", err)
	}
	if row.ApiKey != "" {
		t.Fatalf("no-auth provider stored api_key %q, want explicit empty string", row.ApiKey)
	}
	resp := h.Do(h.NewRequest(http.MethodPatch, "/api/v1/providers/"+local.Id+"/", token, &airlockv1.UpdateProviderRequest{ApiKey: "temporary-key"}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set local API key: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	updated := &airlockv1.UpdateProviderResponse{}
	h.DecodeProto(resp, updated)
	if !updated.Provider.HasApiKey {
		t.Fatal("updated local provider does not report API key")
	}
	resp = h.Do(h.NewRequest(http.MethodPatch, "/api/v1/providers/"+local.Id+"/", token, &airlockv1.UpdateProviderRequest{ClearApiKey: true}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear local API key: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	updated = &airlockv1.UpdateProviderResponse{}
	h.DecodeProto(resp, updated)
	if updated.Provider.HasApiKey {
		t.Fatal("cleared local provider still reports API key")
	}
	row, err = dbq.New(h.DB.Pool()).GetProviderByID(context.Background(), pgUUID(uuid.MustParse(local.Id)))
	if err != nil {
		t.Fatalf("get cleared local provider: %v", err)
	}
	if row.ApiKey != "" {
		t.Fatalf("cleared local provider stored api_key %q", row.ApiKey)
	}
	resp = h.Do(h.NewRequest(http.MethodPatch, "/api/v1/providers/"+first.Id+"/", token, &airlockv1.UpdateProviderRequest{ClearApiKey: true}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("hosted API key clear: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)

	resp = h.Do(h.NewRequest(http.MethodPatch, "/api/v1/providers/"+second.Id+"/", token, &airlockv1.UpdateProviderRequest{Slug: "team-one"}))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate update: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
}

func TestProviders_DiscoveryAuthAndSafety(t *testing.T) {
	h := apitest.Setup(t)
	admin := apitest.CreateUser(t, h, "discovery-admin", "admin")
	token := apitest.IssueUserToken(t, h, admin, "discovery-admin@apitest.local", "admin")

	var authorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("discovery path = %q, want /v1/models", r.URL.Path)
		}
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"z-model"},{"id":"a-model"}]}`))
	}))
	defer upstream.Close()

	noAuth := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "discover-no-auth", DisplayName: "No Auth", BaseUrl: upstream.URL + "/v1",
	}, http.StatusCreated)
	resp := h.Do(h.NewRequest(http.MethodPost, "/api/v1/providers/"+noAuth.Id+"/discover-models", token, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("no-auth discovery: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	discovered := &airlockv1.DiscoverProviderModelsResponse{}
	h.DecodeProto(resp, discovered)
	if authorization != "" {
		t.Fatalf("no-auth discovery sent Authorization %q", authorization)
	}
	if len(discovered.Candidates) != 2 || discovered.Candidates[0].ModelId != "a-model" || discovered.Candidates[1].ModelId != "z-model" {
		t.Fatalf("unexpected candidates: %+v", discovered.Candidates)
	}

	withAuth := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "discover-bearer", DisplayName: "Bearer", BaseUrl: upstream.URL + "/v1", ApiKey: "secret-token",
	}, http.StatusCreated)
	resp = h.Do(h.NewRequest(http.MethodPost, "/api/v1/providers/"+withAuth.Id+"/discover-models", token, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer discovery: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
	if authorization != "Bearer secret-token" {
		t.Fatalf("bearer discovery Authorization = %q", authorization)
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer redirect.Close()
	redirectProvider := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "discover-redirect", DisplayName: "Redirect", BaseUrl: redirect.URL + "/v1",
	}, http.StatusCreated)
	resp = h.Do(h.NewRequest(http.MethodPost, "/api/v1/providers/"+redirectProvider.Id+"/discover-models", token, nil))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("redirect discovery: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)

	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"data":[{"id":"%s"}]}`, strings.Repeat("x", (1<<20)+1))
	}))
	defer oversized.Close()
	oversizedProvider := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "discover-oversized", DisplayName: "Oversized", BaseUrl: oversized.URL + "/v1",
	}, http.StatusCreated)
	resp = h.Do(h.NewRequest(http.MethodPost, "/api/v1/providers/"+oversizedProvider.Id+"/discover-models", token, nil))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("oversized discovery: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
}

func TestProviderModels_RowSpecificCatalogValidationAndNoKeyRuntime(t *testing.T) {
	h := apitest.Setup(t)
	admin := apitest.CreateUser(t, h, "models-admin", "admin")
	token := apitest.IssueUserToken(t, h, admin, "models-admin@apitest.local", "admin")

	first := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "local-tools", DisplayName: "Local Tools", BaseUrl: "http://localhost:8101/v1",
	}, http.StatusCreated)
	second := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "local-vision", DisplayName: "Local Vision", BaseUrl: "http://localhost:8102/v1",
	}, http.StatusCreated)
	replaceProviderModels(t, h, token, first.Id, &airlockv1.ProviderModel{
		ModelId: "shared-model", DisplayName: "Shared Tools", ToolCall: true,
		ContextLimit: 8192, OutputLimit: 2048, StructuredOutputs: true, IncludeUsage: true,
	})
	replaceProviderModels(t, h, token, second.Id, &airlockv1.ProviderModel{
		ModelId: "shared-model", DisplayName: "Shared Vision", Vision: true,
		ContextLimit: 16384, OutputLimit: 4096,
	})

	resp := h.Do(h.NewRequest(http.MethodGet, "/api/v1/providers/"+first.Id+"/models", token, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list provider models: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	listed := &airlockv1.ListProviderModelsResponse{}
	h.DecodeProto(resp, listed)
	if len(listed.Models) != 1 || listed.Models[0].DisplayName != "Shared Tools" || !listed.Models[0].IncludeUsage {
		t.Fatalf("unexpected provider model list: %+v", listed.Models)
	}
	resp = h.Do(h.NewRequest(http.MethodPut, "/api/v1/providers/"+first.Id+"/models", token, &airlockv1.ReplaceProviderModelsRequest{Models: []*airlockv1.ProviderModel{{
		ModelId: "invalid", DisplayName: "Invalid", ContextLimit: 0, OutputLimit: 1,
	}}}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid replacement: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
	resp = h.Do(h.NewRequest(http.MethodGet, "/api/v1/providers/"+first.Id+"/models", token, nil))
	listed = &airlockv1.ListProviderModelsResponse{}
	h.DecodeProto(resp, listed)
	if len(listed.Models) != 1 || listed.Models[0].ModelId != "shared-model" {
		t.Fatalf("invalid replacement changed persisted models: %+v", listed.Models)
	}

	resp = h.Do(h.NewRequest(http.MethodGet, "/api/v1/catalog/models?provider=openai-compatible&configured=true", token, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("catalog models: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	catalog := &airlockv1.ListCatalogModelsResponse{}
	h.DecodeProto(resp, catalog)
	if len(catalog.Models) != 2 {
		t.Fatalf("local catalog length = %d, want 2", len(catalog.Models))
	}
	byProvider := map[string]*airlockv1.ModelInfo{}
	for _, model := range catalog.Models {
		byProvider[model.ProviderConfigId] = model
	}
	firstModel, ok := byProvider[first.Id]
	if !ok || !firstModel.ToolCall || firstModel.Name != "Shared Tools" {
		t.Fatalf("first row catalog model = %+v", firstModel)
	}
	secondModel, ok := byProvider[second.Id]
	if !ok || !contains(secondModel.Caps, "vision") || secondModel.Name != "Shared Vision" {
		t.Fatalf("second row catalog model = %+v", secondModel)
	}

	resp = h.Do(h.NewRequest(http.MethodGet, "/api/v1/catalog/models?provider="+first.Id, token, nil))
	filtered := &airlockv1.ListCatalogModelsResponse{}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("row-filtered catalog: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.DecodeProto(resp, filtered)
	if len(filtered.Models) != 1 || filtered.Models[0].ProviderConfigId != first.Id {
		t.Fatalf("row-filtered models = %+v", filtered.Models)
	}

	resp = h.Do(h.NewRequest(http.MethodPost, "/api/v1/model-grants/", token, &airlockv1.GrantModelRequest{
		ProviderId: first.Id, Model: "shared-model", GranteeId: authz.GroupUser.String(),
	}))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("grant local model: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()
	allowed := allowedModels(t, h, token)
	if len(allowed.Models) != 1 || allowed.Models[0].ProviderId != first.Id || allowed.Models[0].Model != "shared-model" {
		t.Fatalf("allowed local models = %+v", allowed.Models)
	}
	resp = h.Do(h.NewRequest(http.MethodPut, "/api/v1/providers/"+first.Id+"/models", token, &airlockv1.ReplaceProviderModelsRequest{}))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("remove granted provider model: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
	resp = h.Do(h.NewRequest(http.MethodDelete, "/api/v1/providers/"+first.Id+"/", token, nil))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("delete referenced provider: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
	resp = h.Do(h.NewRequest(http.MethodPut, "/api/v1/providers/"+first.Id+"/models", token, &airlockv1.ReplaceProviderModelsRequest{Models: []*airlockv1.ProviderModel{{
		ModelId: "shared-model", DisplayName: "Shared Tools", ContextLimit: 8192, OutputLimit: 2048,
	}}}))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("downgrade granted provider model: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)

	updateSettings := func(providerID, model string, vision, search bool) int {
		t.Helper()
		settings := &airlockv1.SystemSettingsInfo{}
		if vision {
			settings.DefaultVisionProviderId, settings.DefaultVisionModel = providerID, model
		} else if search {
			settings.DefaultSearchProviderId, settings.DefaultSearchModel = providerID, model
		} else {
			settings.DefaultExecProviderId, settings.DefaultExecModel = providerID, model
		}
		resp := h.Do(h.NewRequest(http.MethodPut, "/api/v1/settings", token, &airlockv1.UpdateSystemSettingsRequest{Settings: settings}))
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if got := updateSettings(first.Id, "shared-model", true, false); got != http.StatusBadRequest {
		t.Fatalf("non-vision local model accepted for vision default: %d", got)
	}
	if got := updateSettings(second.Id, "shared-model", true, false); got != http.StatusOK {
		t.Fatalf("vision local model rejected: %d", got)
	}
	if got := updateSettings(second.Id, "shared-model", false, true); got != http.StatusBadRequest {
		t.Fatalf("non-tool local model accepted for search default: %d", got)
	}
	if got := updateSettings(first.Id, "shared-model", false, true); got != http.StatusBadRequest {
		t.Fatalf("openai-compatible model accepted as a search backend: %d", got)
	}
	if got := updateSettings(first.Id, "shared-model", false, false); got != http.StatusOK {
		t.Fatalf("text local model rejected: %d", got)
	}
	disabled := false
	resp = h.Do(h.NewRequest(http.MethodPatch, "/api/v1/providers/"+first.Id+"/", token, &airlockv1.UpdateProviderRequest{IsEnabled: &disabled}))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("disable assigned provider: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
	resolved, err := servicemodels.SystemDefault(context.Background(), h.DB, h.Secrets, "text")
	if err != nil {
		t.Fatalf("resolve no-key system default: %v", err)
	}
	if resolved.ProviderCatalogID != "openai-compatible" || resolved.ProviderSlug != "local-tools" || resolved.ModelName != "shared-model" || resolved.APIKey != "" || resolved.BaseURL != "http://localhost:8101/v1" {
		t.Fatalf("unexpected no-key resolution: %+v", resolved)
	}
	if resolved.IncludeUsage == nil || !*resolved.IncludeUsage || resolved.SupportsStructuredOutputs == nil || !*resolved.SupportsStructuredOutputs {
		t.Fatalf("endpoint model options were not resolved exactly: %+v", resolved)
	}

	resp = h.Do(h.NewRequest(http.MethodPatch, "/api/v1/providers/"+second.Id+"/", token, &airlockv1.UpdateProviderRequest{IsEnabled: &disabled}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable provider: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
	if got := updateSettings(second.Id, "shared-model", false, false); got != http.StatusBadRequest {
		t.Fatalf("disabled provider accepted for default: %d", got)
	}
	resp = h.Do(h.NewRequest(http.MethodGet, "/api/v1/catalog/models?provider=openai-compatible&configured=true", token, nil))
	catalog = &airlockv1.ListCatalogModelsResponse{}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("catalog after disable: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.DecodeProto(resp, catalog)
	if len(catalog.Models) != 1 || catalog.Models[0].ProviderConfigId != first.Id {
		t.Fatalf("disabled row remained in catalog: %+v", catalog.Models)
	}

	grantOnly := createProvider(t, h, token, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "grant-only", DisplayName: "Grant Only", BaseUrl: "http://localhost:8104/v1",
	}, http.StatusCreated)
	replaceProviderModels(t, h, token, grantOnly.Id, &airlockv1.ProviderModel{
		ModelId: "grant-only-model", DisplayName: "Grant Only Model", ContextLimit: 4096, OutputLimit: 1024,
	})
	resp = h.Do(h.NewRequest(http.MethodPost, "/api/v1/model-grants/", token, &airlockv1.GrantModelRequest{
		ProviderId: grantOnly.Id, Model: "grant-only-model", GranteeId: authz.GroupUser.String(),
	}))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("grant-only model grant: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()
	resp = h.Do(h.NewRequest(http.MethodPatch, "/api/v1/providers/"+grantOnly.Id+"/", token, &airlockv1.UpdateProviderRequest{IsEnabled: &disabled}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable grant-only provider: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	h.ReadBody(resp)
}

func TestProviderModelEndpointsRequireAdmin(t *testing.T) {
	h := apitest.Setup(t)
	admin := apitest.CreateUser(t, h, "provider-auth-admin", "admin")
	adminToken := apitest.IssueUserToken(t, h, admin, "provider-auth-admin@apitest.local", "admin")
	user := apitest.CreateUser(t, h, "provider-auth-user", "user")
	userToken := apitest.IssueUserToken(t, h, user, "provider-auth-user@apitest.local", "user")
	provider := createProvider(t, h, adminToken, &airlockv1.CreateProviderRequest{
		ProviderId: "openai-compatible", Slug: "auth-local", DisplayName: "Auth Local", BaseUrl: "http://localhost:8103/v1",
	}, http.StatusCreated)

	for _, tc := range []struct {
		method, path string
		body         *airlockv1.ReplaceProviderModelsRequest
	}{
		{method: http.MethodGet, path: "/api/v1/providers/" + provider.Id + "/models"},
		{method: http.MethodPut, path: "/api/v1/providers/" + provider.Id + "/models", body: &airlockv1.ReplaceProviderModelsRequest{}},
		{method: http.MethodPost, path: "/api/v1/providers/" + provider.Id + "/discover-models"},
	} {
		resp := h.Do(h.NewRequest(tc.method, tc.path, userToken, tc.body))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s: status %d, want 403, body %s", tc.method, tc.path, resp.StatusCode, h.ReadBody(resp))
		}
		h.ReadBody(resp)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
