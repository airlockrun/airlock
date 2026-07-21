package apitest_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	needssvc "github.com/airlockrun/airlock/service/needs"
	"github.com/airlockrun/goai/mcp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// seedConnection creates a token connection owned by the agent's user, declares
// a need for it, and binds it (so agent_count = 1). With withToken it reads as
// authorized. Returns the connection id.
func seedConnection(t *testing.T, h *apitest.Harness, agentID uuid.UUID, slug string, withToken bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	q := dbq.New(h.DB.Pool())
	conn, err := q.UpsertConnection(ctx, dbq.UpsertConnectionParams{
		AgentID: pgUUID(agentID), Slug: slug, Name: "Conn " + slug, DisplayName: "Conn " + slug, AuthMode: "token",
		AuthInjection: []byte(`{"type":"bearer"}`), Config: []byte("{}"),
		AuthParams: []byte("{}"), Headers: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	if err := q.UpsertResourceNeed(ctx, dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(agentID), Type: "connection", Slug: slug, Description: "Conn " + slug,
		Spec: []byte("{}"),
	}); err != nil {
		t.Fatalf("seed need: %v", err)
	}
	if _, err := q.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{
		AgentID: pgUUID(agentID), Slug: slug, ResourceID: conn.ID,
	}); err != nil {
		t.Fatalf("bind need: %v", err)
	}
	if withToken {
		if err := q.UpdateConnectionCredentialsByID(ctx, dbq.UpdateConnectionCredentialsByIDParams{
			ID: conn.ID, AccessTokenRef: "secret-ref",
		}); err != nil {
			t.Fatalf("seed token: %v", err)
		}
	}
	return uuid.UUID(conn.ID.Bytes)
}

func listResources(t *testing.T, h *apitest.Harness, token string) *airlockv1.ListOwnedResourcesResponse {
	t.Helper()
	resp := h.Do(h.NewRequest(http.MethodGet, "/api/v1/resources", token, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list resources: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	out := &airlockv1.ListOwnedResourcesResponse{}
	h.DecodeProto(resp, out)
	return out
}

// TestResources_OwnerScoped verifies ungranted resources remain owner-scoped.
func TestResources_OwnerScoped(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "owner", "user")
	stranger := apitest.CreateUser(t, h, "stranger", "user")
	ownerTok := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")
	strangerTok := apitest.IssueUserToken(t, h, stranger, "stranger@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	seedConnection(t, h, agentID, "github", true)

	owned := listResources(t, h, ownerTok)
	if len(owned.Resources) != 1 {
		t.Fatalf("owner: want 1 resource, got %d", len(owned.Resources))
	}
	r := owned.Resources[0]
	if r.Type != "connection" || r.Slug != "github" {
		t.Errorf("unexpected resource: type=%q slug=%q", r.Type, r.Slug)
	}
	if !r.Authorized {
		t.Error("want authorized=true (token set)")
	}
	if r.AgentCount != 1 {
		t.Errorf("want agentCount=1, got %d", r.AgentCount)
	}

	if other := listResources(t, h, strangerTok); len(other.Resources) != 0 {
		t.Errorf("stranger: want 0 resources, got %d", len(other.Resources))
	}
}

// TestResources_RevokeGating verifies a caller without manage cannot revoke.
func TestResources_RevokeGating(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "owner", "user")
	stranger := apitest.CreateUser(t, h, "stranger", "user")
	ownerTok := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")
	strangerTok := apitest.IssueUserToken(t, h, stranger, "stranger@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	connID := seedConnection(t, h, agentID, "github", true)

	revoke := func(tok string) int {
		return h.Do(h.NewRequest(http.MethodPost, "/api/v1/resources/connection/"+connID.String()+"/revoke", tok, nil)).StatusCode
	}

	if code := revoke(strangerTok); code != http.StatusForbidden {
		t.Fatalf("stranger revoke: want 403, got %d", code)
	}
	if !listResources(t, h, ownerTok).Resources[0].Authorized {
		t.Error("token should survive a rejected revoke")
	}
	if code := revoke(ownerTok); code != http.StatusNoContent {
		t.Fatalf("owner revoke: want 204, got %d", code)
	}
	if listResources(t, h, ownerTok).Resources[0].Authorized {
		t.Error("want authorized=false after revoke")
	}
}

// TestResources_DeleteGating verifies manage permission and ON DELETE unbinding.
func TestResources_DeleteGating(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "owner", "user")
	stranger := apitest.CreateUser(t, h, "stranger", "user")
	ownerTok := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")
	strangerTok := apitest.IssueUserToken(t, h, stranger, "stranger@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	connID := seedConnection(t, h, agentID, "github", true)

	del := func(tok string) int {
		return h.Do(h.NewRequest(http.MethodDelete, "/api/v1/resources/connection/"+connID.String(), tok, nil)).StatusCode
	}

	if code := del(strangerTok); code != http.StatusForbidden {
		t.Fatalf("stranger delete: want 403, got %d", code)
	}
	if len(listResources(t, h, ownerTok).Resources) != 1 {
		t.Error("resource should survive a rejected delete")
	}
	if code := del(ownerTok); code != http.StatusNoContent {
		t.Fatalf("owner delete: want 204, got %d", code)
	}
	if n := len(listResources(t, h, ownerTok).Resources); n != 0 {
		t.Errorf("want 0 resources after delete, got %d", n)
	}

	need, err := dbq.New(h.DB.Pool()).GetResourceNeed(context.Background(), dbq.GetResourceNeedParams{
		AgentID: pgUUID(agentID), Type: "connection", Slug: "github",
	})
	if err != nil {
		t.Fatalf("need should still exist after resource delete: %v", err)
	}
	if need.BoundConnectionID.Valid {
		t.Error("need should be unbound after resource delete")
	}
}

func TestResources_RenameRequiresManageAndAllowsDuplicates(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "rename-owner", "user")
	manager := apitest.CreateUser(t, h, "rename-manager", "user")
	ownerTok := apitest.IssueUserToken(t, h, owner, "rename-owner@apitest.local", "user")
	managerTok := apitest.IssueUserToken(t, h, manager, "rename-manager@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	firstID := seedConnection(t, h, agentID, "first", false)
	secondID := seedConnection(t, h, agentID, "second", false)

	rename := func(token string, id uuid.UUID, displayName string) int {
		resp := h.Do(h.NewRequest(http.MethodPatch, "/api/v1/resources/connection/"+id.String(), token, &airlockv1.RenameResourceRequest{DisplayName: displayName}))
		return resp.StatusCode
	}
	if code := rename(managerTok, firstID, "Shared name"); code != http.StatusForbidden {
		t.Fatalf("rename without manage: want 403, got %d", code)
	}
	q := dbq.New(h.DB.Pool())
	if _, err := q.CreateConnectionGrant(context.Background(), dbq.CreateConnectionGrantParams{
		ConnectionID: pgUUID(firstID), GranteeID: pgUUID(manager), Capabilities: []string{"manage"},
	}); err != nil {
		t.Fatalf("grant manage: %v", err)
	}
	if code := rename(managerTok, firstID, "  Shared name  "); code != http.StatusNoContent {
		t.Fatalf("granted rename: want 204, got %d", code)
	}
	if code := rename(ownerTok, secondID, "Shared name"); code != http.StatusNoContent {
		t.Fatalf("duplicate display name: want 204, got %d", code)
	}
	if code := rename(managerTok, firstID, "   "); code != http.StatusBadRequest {
		t.Fatalf("blank display name: want 400, got %d", code)
	}

	resources := listResources(t, h, ownerTok).Resources
	if len(resources) != 2 {
		t.Fatalf("want 2 resources, got %d", len(resources))
	}
	for _, resource := range resources {
		if resource.DisplayName != "Shared name" {
			t.Errorf("display name = %q, want Shared name", resource.DisplayName)
		}
		if resource.Name != "Conn "+resource.Slug {
			t.Errorf("declaration name changed: got %q for slug %q", resource.Name, resource.Slug)
		}
	}
}

func TestResources_ConsumersRequireViewCapability(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "consumer-owner", "user")
	viewer := apitest.CreateUser(t, h, "consumer-viewer", "user")
	ownerTok := apitest.IssueUserToken(t, h, owner, "consumer-owner@apitest.local", "user")
	viewerTok := apitest.IssueUserToken(t, h, viewer, "consumer-viewer@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner, Name: "Consumer Agent", Slug: "consumer-agent"})
	connID := seedConnection(t, h, agentID, "github", false)
	path := "/api/v1/resources/connection/" + connID.String() + "/consumers"

	if code := h.Do(h.NewRequest(http.MethodGet, path, viewerTok, nil)).StatusCode; code != http.StatusForbidden {
		t.Fatalf("consumers without view: want 403, got %d", code)
	}
	q := dbq.New(h.DB.Pool())
	grant, err := q.CreateConnectionGrant(context.Background(), dbq.CreateConnectionGrantParams{
		ConnectionID: pgUUID(connID), GranteeID: pgUUID(viewer), Capabilities: []string{"view"},
	})
	if err != nil {
		t.Fatalf("grant view: %v", err)
	}
	resp := h.Do(h.NewRequest(http.MethodGet, path, viewerTok, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("consumers with view: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	out := &airlockv1.ListResourceConsumersResponse{}
	h.DecodeProto(resp, out)
	if len(out.Consumers) != 1 {
		t.Fatalf("want 1 consumer, got %d", len(out.Consumers))
	}
	consumer := out.Consumers[0]
	if consumer.AgentId != agentID.String() || consumer.AgentName != "Consumer Agent" || consumer.AgentSlug != "consumer-agent" || consumer.NeedType != "connection" || consumer.NeedSlug != "github" {
		t.Errorf("unexpected consumer: %+v", consumer)
	}
	if consumer.CanAccessAgent {
		t.Error("resource viewer without agent membership was marked accessible")
	}
	grantsPath := "/api/v1/resources/connection/" + connID.String() + "/grants"
	if code := h.Do(h.NewRequest(http.MethodGet, grantsPath, viewerTok, nil)).StatusCode; code != http.StatusForbidden {
		t.Fatalf("grant list with view only: want 403, got %d", code)
	}
	ownerResp := h.Do(h.NewRequest(http.MethodGet, path, ownerTok, nil))
	ownerConsumers := &airlockv1.ListResourceConsumersResponse{}
	h.DecodeProto(ownerResp, ownerConsumers)
	if len(ownerConsumers.Consumers) != 1 || !ownerConsumers.Consumers[0].CanAccessAgent {
		t.Fatalf("agent owner accessibility missing: %+v", ownerConsumers.Consumers)
	}

	grantsResp := h.Do(h.NewRequest(http.MethodGet, grantsPath, ownerTok, nil))
	grants := &airlockv1.ListResourceGrantsResponse{}
	h.DecodeProto(grantsResp, grants)
	if len(grants.Grants) != 1 || grants.Grants[0].Id != uuid.UUID(grant.ID.Bytes).String() {
		t.Errorf("grant ID missing from response: %+v", grants.Grants)
	}
}

func TestNeeds_GrantBasedCandidatesBindingAndUnbind(t *testing.T) {
	h := apitest.Setup(t)
	resourceOwner := apitest.CreateUser(t, h, "resource-owner", "user")
	consumer := apitest.CreateUser(t, h, "resource-consumer", "user")
	consumerTok := apitest.IssueUserToken(t, h, consumer, "resource-consumer@apitest.local", "user")
	ownerAgent := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: resourceOwner, Slug: "resource-owner-agent"})
	consumerAgent := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: consumer, Slug: "resource-consumer-agent"})
	connID := seedConnection(t, h, ownerAgent, "github", false)
	q := dbq.New(h.DB.Pool())
	spec := []byte(`{"base_url":"","auth_mode":"token","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`)
	if err := q.UpsertResourceNeed(context.Background(), dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(consumerAgent), Type: "connection", Slug: "source-control", Description: "Source control", Spec: spec,
	}); err != nil {
		t.Fatalf("seed consumer need: %v", err)
	}
	basePath := "/api/v1/agents/" + consumerAgent.String() + "/needs/connection/source-control"

	bind := func() int {
		return h.Do(h.NewRequest(http.MethodPost, basePath+"/bind", consumerTok, &airlockv1.BindNeedRequest{ResourceId: connID.String()})).StatusCode
	}
	if code := bind(); code != http.StatusForbidden {
		t.Fatalf("bind without resource grant: want 403, got %d", code)
	}
	grant, err := q.CreateConnectionGrant(context.Background(), dbq.CreateConnectionGrantParams{
		ConnectionID: pgUUID(connID), GranteeID: pgUUID(consumer), Capabilities: []string{"bind"},
	})
	if err != nil {
		t.Fatalf("grant bind: %v", err)
	}

	candidatesResp := h.Do(h.NewRequest(http.MethodGet, basePath+"/candidates", consumerTok, nil))
	if candidatesResp.StatusCode != http.StatusOK {
		t.Fatalf("list candidates: status %d, body %s", candidatesResp.StatusCode, h.ReadBody(candidatesResp))
	}
	candidates := &airlockv1.ListCandidatesResponse{}
	h.DecodeProto(candidatesResp, candidates)
	if len(candidates.Candidates) != 1 || candidates.Candidates[0].ResourceId != connID.String() || candidates.Candidates[0].DisplayName != "Conn github" {
		t.Fatalf("unexpected candidates: %+v", candidates.Candidates)
	}
	available := listResources(t, h, consumerTok)
	if len(available.Resources) != 1 || len(available.Resources[0].Capabilities) != 1 || available.Resources[0].Capabilities[0] != "bind" {
		t.Fatalf("grant-based inventory missing caller capabilities: %+v", available.Resources)
	}
	if code := bind(); code != http.StatusNoContent {
		t.Fatalf("bind with resource grant: want 204, got %d", code)
	}

	if _, err := q.RevokeResourceGrant(context.Background(), dbq.RevokeResourceGrantParams{
		ID: grant.ID, ResourceType: "connection", ResourceID: pgUUID(connID),
	}); err != nil {
		t.Fatalf("revoke bind grant: %v", err)
	}
	if code := h.Do(h.NewRequest(http.MethodDelete, basePath+"/bind", consumerTok, nil)).StatusCode; code != http.StatusNoContent {
		t.Fatalf("unbind without resource permission: want 204, got %d", code)
	}
	consumerNeed, err := q.GetResourceNeed(context.Background(), dbq.GetResourceNeedParams{
		AgentID: pgUUID(consumerAgent), Type: "connection", Slug: "source-control",
	})
	if err != nil {
		t.Fatalf("get consumer need: %v", err)
	}
	if consumerNeed.BoundConnectionID.Valid {
		t.Error("consumer need remains bound after unbind")
	}
	ownerNeed, err := q.GetResourceNeed(context.Background(), dbq.GetResourceNeedParams{
		AgentID: pgUUID(ownerAgent), Type: "connection", Slug: "github",
	})
	if err != nil || !ownerNeed.BoundConnectionID.Valid || uuid.UUID(ownerNeed.BoundConnectionID.Bytes) != connID {
		t.Fatalf("other binding changed: need=%+v err=%v", ownerNeed, err)
	}
	if _, err := q.GetConnectionByID(context.Background(), pgUUID(connID)); err != nil {
		t.Fatalf("resource deleted by unbind: %v", err)
	}
	missingPath := "/api/v1/agents/" + consumerAgent.String() + "/needs/connection/missing/bind"
	if code := h.Do(h.NewRequest(http.MethodDelete, missingPath, consumerTok, nil)).StatusCode; code != http.StatusNotFound {
		t.Fatalf("unbind missing need: want 404, got %d", code)
	}
}

func TestResources_NoAuthMCPIsReady(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "mcp-owner", "user")
	token := apitest.IssueUserToken(t, h, owner, "mcp-owner@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	q := dbq.New(h.DB.Pool())
	server, err := q.UpsertMCPServer(context.Background(), dbq.UpsertMCPServerParams{
		AgentID: pgUUID(agentID), Slug: "public-mcp", Name: "Public MCP", DisplayName: "Public MCP",
		Url: "https://mcp.example.com", AuthMode: "none", AuthInjection: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("seed no-auth MCP: %v", err)
	}
	if server.DisplayName != "Public MCP" {
		t.Fatalf("display name = %q", server.DisplayName)
	}
	resources := listResources(t, h, token)
	if len(resources.Resources) != 1 || !resources.Resources[0].Authorized {
		t.Fatalf("no-auth MCP should be ready: %+v", resources.Resources)
	}
}

func seedOAuthConnection(t *testing.T, h *apitest.Harness, agentID uuid.UUID, slug, scopes, granted string) uuid.UUID {
	t.Helper()
	q := dbq.New(h.DB.Pool())
	conn, err := q.UpsertConnection(context.Background(), dbq.UpsertConnectionParams{
		AgentID: pgUUID(agentID), Slug: slug, Name: "OAuth resource", DisplayName: "OAuth resource",
		AuthMode: "oauth", AuthUrl: "https://provider.example/authorize", TokenUrl: "https://provider.example/token",
		BaseUrl: "https://api.example.com", Scopes: scopes, AuthInjection: []byte(`{"type":"bearer"}`),
		Config: []byte("{}"), AuthParams: []byte("{}"), Headers: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("seed OAuth connection: %v", err)
	}
	if err := q.UpdateConnectionCredentialsByID(context.Background(), dbq.UpdateConnectionCredentialsByIDParams{
		ID: conn.ID, AccessTokenRef: "access-ref", GrantedScopes: granted, ScopesVerified: true,
	}); err != nil {
		t.Fatalf("seed OAuth grant: %v", err)
	}
	return uuid.UUID(conn.ID.Bytes)
}

func seedConnectionNeed(t *testing.T, h *apitest.Harness, agentID uuid.UUID, slug, scopes string) {
	t.Helper()
	if err := dbq.New(h.DB.Pool()).UpsertResourceNeed(context.Background(), dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(agentID), Type: "connection", Slug: slug, Description: "OAuth need",
		ExpectedUrl: "https://api.example.com", ExpectedScopes: scopes,
		Spec: []byte(`{"name":"OAuth","base_url":"https://api.example.com","auth_mode":"oauth","scopes":"` + scopes + `","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`),
	}); err != nil {
		t.Fatalf("seed OAuth need: %v", err)
	}
}

func TestNeeds_OAuthScopeReadinessAndBindCapabilities(t *testing.T) {
	h := apitest.Setup(t)
	resourceOwner := apitest.CreateUser(t, h, "scope-resource-owner", "user")
	consumer := apitest.CreateUser(t, h, "scope-consumer", "user")
	consumerToken := apitest.IssueUserToken(t, h, consumer, "scope-consumer@apitest.local", "user")
	ownerAgent := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: resourceOwner, Slug: "scope-owner-agent"})
	targetAgent := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: consumer, Slug: "scope-target-agent"})
	readyID := seedOAuthConnection(t, h, ownerAgent, "ready", "read write", "read write")
	missingID := seedOAuthConnection(t, h, ownerAgent, "missing", "read", "read")
	unverifiedID := seedOAuthConnection(t, h, ownerAgent, "unverified", "read write", "read write")
	if _, err := h.DB.Pool().Exec(t.Context(), `UPDATE connections SET access_token_ref='', refresh_token='', scopes_verified=false WHERE id=$1`, pgUUID(unverifiedID)); err != nil {
		t.Fatal(err)
	}
	seedConnectionNeed(t, h, targetAgent, "documents", "read write")
	q := dbq.New(h.DB.Pool())
	for _, id := range []uuid.UUID{readyID, missingID, unverifiedID} {
		if _, err := q.CreateConnectionGrant(context.Background(), dbq.CreateConnectionGrantParams{
			ConnectionID: pgUUID(id), GranteeID: pgUUID(consumer), Capabilities: []string{"bind"},
		}); err != nil {
			t.Fatalf("grant bind: %v", err)
		}
	}
	base := "/api/v1/agents/" + targetAgent.String() + "/needs/connection/documents"
	resp := h.Do(h.NewRequest(http.MethodGet, base+"/candidates", consumerToken, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list candidates: %d %s", resp.StatusCode, h.ReadBody(resp))
	}
	list := &airlockv1.ListCandidatesResponse{}
	h.DecodeProto(resp, list)
	if len(list.Candidates) != 3 {
		t.Fatalf("candidates = %d, want 3", len(list.Candidates))
	}
	byID := map[string]*airlockv1.CandidateInfo{}
	for _, candidate := range list.Candidates {
		byID[candidate.ResourceId] = candidate
	}
	if got := byID[readyID.String()]; got == nil || got.Readiness != "ready" || !got.Authorized || got.AgentCount != 0 {
		t.Fatalf("ready candidate = %+v", got)
	}
	if got := byID[missingID.String()]; got == nil || got.Readiness != "scope_upgrade_requires_manager" || len(got.MissingScopes) != 1 || got.MissingScopes[0] != "write" {
		t.Fatalf("underscoped candidate = %+v", got)
	}
	if got := byID[unverifiedID.String()]; got == nil || got.Readiness != "scope_upgrade_requires_manager" || len(got.MissingScopes) != 0 {
		t.Fatalf("unverified candidate = %+v", got)
	}

	bind := func(id uuid.UUID) int {
		return h.Do(h.NewRequest(http.MethodPost, base+"/bind", consumerToken, &airlockv1.BindNeedRequest{ResourceId: id.String()})).StatusCode
	}
	if code := bind(missingID); code != http.StatusConflict {
		t.Fatalf("underscoped bind status = %d, want 409", code)
	}
	if code := bind(unverifiedID); code != http.StatusConflict {
		t.Fatalf("unverified bind status = %d, want 409", code)
	}
	need, err := q.GetResourceNeed(context.Background(), dbq.GetResourceNeedParams{AgentID: pgUUID(targetAgent), Type: "connection", Slug: "documents"})
	if err != nil || need.BoundConnectionID.Valid {
		t.Fatalf("underscoped bind mutated need: %+v, %v", need, err)
	}
	if code := bind(readyID); code != http.StatusNoContent {
		t.Fatalf("ready bind status = %d, want 204", code)
	}
}

func TestNeeds_GeneratedSlugsAllowIndependentSameLocalSlug(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "same-slug-owner", "user")
	token := apitest.IssueUserToken(t, h, owner, "same-slug-owner@apitest.local", "user")
	q := dbq.New(h.DB.Pool())
	var ids []uuid.UUID
	for i := 0; i < 2; i++ {
		agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
		if err := q.UpsertResourceNeed(context.Background(), dbq.UpsertResourceNeedParams{
			AgentID: pgUUID(agentID), Type: "connection", Slug: "api", Description: "Public API",
			Spec: []byte(`{"name":"Public API","base_url":"https://api.example.com","auth_mode":"none","auth_injection":{},"auth_params":{},"headers":{}}`),
		}); err != nil {
			t.Fatalf("seed need: %v", err)
		}
		path := "/api/v1/agents/" + agentID.String() + "/needs/connection/api/create"
		resp := h.Do(h.NewRequest(http.MethodPost, path, token, &airlockv1.CreateForNeedRequest{DisplayName: "Public API"}))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create resource: %d %s", resp.StatusCode, h.ReadBody(resp))
		}
		created := &airlockv1.CreateForNeedResponse{}
		h.DecodeProto(resp, created)
		ids = append(ids, uuid.MustParse(created.ResourceId))
	}
	if ids[0] == ids[1] {
		t.Fatal("same local need slug reused a concrete resource")
	}
	for _, id := range ids {
		resource, err := q.GetConnectionByID(context.Background(), pgUUID(id))
		if err != nil {
			t.Fatal(err)
		}
		want := "res-" + strings.ReplaceAll(id.String(), "-", "")
		if resource.Slug != want {
			t.Fatalf("resource slug = %q, want %q", resource.Slug, want)
		}
	}
}

func TestNeeds_CreateNewReplacesBoundResourceWithDistinctID(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "create-new-owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	principal := authz.UserPrincipal(owner, auth.RoleUser)
	svc := needssvc.NewService(h.DB, func(context.Context, uuid.UUID) error { return nil }, zap.NewNop())
	q := dbq.New(h.DB.Pool())

	tests := []struct {
		name string
		typ  string
		slug string
		spec string
	}{
		{name: "no-auth connection", typ: "connection", slug: "public-api", spec: `{"name":"Public API","auth_mode":"none","base_url":"https://api.example.com","auth_injection":{},"auth_params":{},"headers":{}}`},
		{name: "API-key connection", typ: "connection", slug: "private-api", spec: `{"name":"Private API","auth_mode":"token","base_url":"https://api.example.com","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`},
		{name: "token MCP", typ: "mcp_server", slug: "private-mcp", spec: `{"name":"Private MCP","auth_mode":"token","url":"https://mcp.example.com","auth_injection":{"type":"bearer"}}`},
		{name: "exec endpoint", typ: "exec_endpoint", slug: "shell", spec: `{"access":"admin","llm_hint":"Remote shell"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := q.UpsertResourceNeed(t.Context(), dbq.UpsertResourceNeedParams{
				AgentID: pgUUID(agentID), Type: tc.typ, Slug: tc.slug, Description: tc.slug, Spec: []byte(tc.spec),
			}); err != nil {
				t.Fatal(err)
			}
			first, err := svc.CreateResourceForNeed(t.Context(), principal, agentID, tc.typ, tc.slug, "First")
			if err != nil {
				t.Fatal(err)
			}
			second, err := svc.CreateResourceForNeed(t.Context(), principal, agentID, tc.typ, tc.slug, "Second")
			if err != nil {
				t.Fatal(err)
			}
			if first == second {
				t.Fatal("create-new reused the bound resource")
			}
			need, err := q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(agentID), Type: tc.typ, Slug: tc.slug})
			if err != nil {
				t.Fatal(err)
			}
			bound := need.BoundConnectionID
			if tc.typ == "mcp_server" {
				bound = need.BoundMcpID
			} else if tc.typ == "exec_endpoint" {
				bound = need.BoundExecID
			}
			if !bound.Valid || uuid.UUID(bound.Bytes) != second {
				t.Fatalf("binding = %v, want %s", bound, second)
			}
		})
	}
}

func TestNeeds_CreateNoAuthMCPRequiresDiscovery(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "no-auth-create-owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	q := dbq.New(h.DB.Pool())
	if err := q.UpsertResourceNeed(t.Context(), dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(agentID), Type: "mcp_server", Slug: "public", Description: "Public MCP",
		Spec: []byte(`{"name":"Public MCP","auth_mode":"none","url":"https://mcp.example.com","auth_injection":{}}`),
	}); err != nil {
		t.Fatal(err)
	}
	svc := needssvc.NewService(h.DB, func(context.Context, uuid.UUID) error { return nil }, zap.NewNop())
	_, err := svc.CreateResourceForNeed(t.Context(), authz.UserPrincipal(owner, auth.RoleUser), agentID, "mcp_server", "public", "Public")
	if !errors.Is(err, service.ErrInvalidInput) || !strings.Contains(err.Error(), "tool discovery") {
		t.Fatalf("CreateResourceForNeed() error = %v", err)
	}
}

func TestNeeds_MCPBindAndCreateRefreshAgentAfterCommit(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "mcp-refresh-owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	principal := authz.UserPrincipal(owner, auth.RoleUser)
	q := dbq.New(h.DB.Pool())
	var refreshed []uuid.UUID
	svc := needssvc.NewService(h.DB, func(_ context.Context, id uuid.UUID) error {
		refreshed = append(refreshed, id)
		return errors.New("stopped agent")
	}, zap.NewNop())

	if err := q.UpsertResourceNeed(t.Context(), dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(agentID), Type: "mcp_server", Slug: "created", Description: "Created",
		Spec: []byte(`{"name":"Created","auth_mode":"token","url":"https://mcp.example.com","auth_injection":{"type":"bearer"}}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateResourceForNeed(t.Context(), principal, agentID, "mcp_server", "created", "Created"); err != nil {
		t.Fatalf("create MCP: %v", err)
	}

	server, err := q.UpsertMCPServer(t.Context(), dbq.UpsertMCPServerParams{
		AgentID: pgUUID(agentID), Slug: "existing", Name: "Existing", DisplayName: "Existing", Url: "https://existing.example.com",
		AuthMode: "none", AuthInjection: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.UpdateMCPServerToolSchemasByID(t.Context(), dbq.UpdateMCPServerToolSchemasByIDParams{ID: server.ID, ToolSchemas: []byte(`[{"name":"ready"}]`)}); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertResourceNeed(t.Context(), dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(agentID), Type: "mcp_server", Slug: "bound", Description: "Bound",
		Spec: []byte(`{"name":"Existing","auth_mode":"none","url":"https://existing.example.com","auth_injection":{}}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindExisting(t.Context(), principal, agentID, "mcp_server", "bound", uuid.UUID(server.ID.Bytes)); err != nil {
		t.Fatalf("bind MCP: %v", err)
	}
	if len(refreshed) != 2 || refreshed[0] != agentID || refreshed[1] != agentID {
		t.Fatalf("refresh calls = %v, want agent twice", refreshed)
	}
}

func TestCredentialConfigureConcurrentCreateUsesOneResource(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "configure-race-owner", "user")
	token := apitest.IssueUserToken(t, h, owner, "configure-race-owner@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	q := dbq.New(h.DB.Pool())
	if err := q.UpsertResourceNeed(t.Context(), dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(agentID), Type: "connection", Slug: "api", Description: "API",
		Spec: []byte(`{"name":"API","auth_mode":"token","base_url":"https://api.example.com","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`),
	}); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/agents/" + agentID.String() + "/credentials/api"
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.Do(h.NewRequest(http.MethodPost, path, token, &airlockv1.SetAPIKeyRequest{ApiKey: uuid.NewString(), DisplayName: "API"}))
			statuses <- resp.StatusCode
			resp.Body.Close()
		}()
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("configure status = %d", status)
		}
	}
	resources := listResources(t, h, token).Resources
	if len(resources) != 1 {
		t.Fatalf("concurrent configure created %d resources, want 1", len(resources))
	}
	need, err := q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(agentID), Type: "connection", Slug: "api"})
	if err != nil || !need.BoundConnectionID.Valid || uuid.UUID(need.BoundConnectionID.Bytes).String() != resources[0].Id {
		t.Fatalf("binding/resource mismatch: need=%+v resources=%+v err=%v", need, resources, err)
	}
}

func TestCredentialConfigurationRequiresDisplayNameForCreation(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "display-owner", "user")
	token := apitest.IssueUserToken(t, h, owner, "display-owner@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	q := dbq.New(h.DB.Pool())
	needs := []dbq.UpsertResourceNeedParams{
		{AgentID: pgUUID(agentID), Type: "connection", Slug: "token", Description: "Token description", Spec: []byte(`{"name":"Declared API","auth_mode":"token","base_url":"https://api.example.com","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`)},
		{AgentID: pgUUID(agentID), Type: "connection", Slug: "oauth", Description: "OAuth description", Spec: []byte(`{"name":"Declared OAuth","auth_mode":"oauth","auth_url":"https://provider.example/authorize","token_url":"https://provider.example/token","base_url":"https://api.example.com","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`)},
		{AgentID: pgUUID(agentID), Type: "mcp_server", Slug: "mcp-token", Description: "Token MCP description", Spec: []byte(`{"name":"Declared Token MCP","auth_mode":"token","url":"http://127.0.0.1:1","auth_injection":{"type":"bearer"}}`)},
		{AgentID: pgUUID(agentID), Type: "mcp_server", Slug: "mcp-oauth", Description: "OAuth MCP description", Spec: []byte(`{"name":"Declared OAuth MCP","auth_mode":"oauth","auth_url":"https://provider.example/authorize","token_url":"https://provider.example/token","url":"https://mcp.example.com","auth_injection":{"type":"bearer"}}`)},
		{AgentID: pgUUID(agentID), Type: "exec_endpoint", Slug: "shell", Description: "Remote shell", Spec: []byte(`{"access":"admin"}`)},
	}
	for _, need := range needs {
		if err := q.UpsertResourceNeed(t.Context(), need); err != nil {
			t.Fatal(err)
		}
	}

	requests := []struct {
		method      string
		path        string
		displayName string
		body        any
	}{
		{http.MethodPost, "/api/v1/agents/" + agentID.String() + "/credentials/token", "Token connection", &airlockv1.SetAPIKeyRequest{ApiKey: "secret"}},
		{http.MethodPut, "/api/v1/agents/" + agentID.String() + "/credentials/oauth/oauth-app", "OAuth connection", &airlockv1.SetOAuthAppRequest{ClientId: "client", ClientSecret: "secret"}},
		{http.MethodPost, "/api/v1/agents/" + agentID.String() + "/mcp-servers/mcp-token/credentials", "Token MCP", &airlockv1.SetAPIKeyRequest{ApiKey: "secret"}},
		{http.MethodPut, "/api/v1/agents/" + agentID.String() + "/mcp-servers/mcp-oauth/credentials/oauth-app", "OAuth MCP", &airlockv1.SetOAuthAppRequest{ClientId: "client", ClientSecret: "secret"}},
		{http.MethodPut, "/api/v1/agents/" + agentID.String() + "/exec-endpoints/shell", "Shell", &airlockv1.ConfigureExecEndpointRequest{Host: "host.example", SshUser: "deploy"}},
	}
	for _, request := range requests {
		resp := h.Do(h.NewRequest(request.method, request.path, token, request.body))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("blank display name %s %s = %d, want 400: %s", request.method, request.path, resp.StatusCode, h.ReadBody(resp))
		}
		resp.Body.Close()
		switch body := request.body.(type) {
		case *airlockv1.SetAPIKeyRequest:
			body.DisplayName = request.displayName
		case *airlockv1.SetOAuthAppRequest:
			body.DisplayName = request.displayName
		case *airlockv1.ConfigureExecEndpointRequest:
			body.DisplayName = request.displayName
		}
		resp = h.Do(h.NewRequest(request.method, request.path, token, request.body))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("named creation %s %s = %d: %s", request.method, request.path, resp.StatusCode, h.ReadBody(resp))
		}
		resp.Body.Close()
	}

	assertConnectionName := func(slug, want string, provisional bool) {
		t.Helper()
		need, err := q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(agentID), Type: "connection", Slug: slug})
		if err != nil {
			t.Fatal(err)
		}
		var row dbq.Connection
		if provisional {
			row, err = q.GetProvisionalConnectionForNeedOwner(t.Context(), dbq.GetProvisionalConnectionForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: pgUUID(owner)})
		} else {
			row, err = q.GetConnectionByID(t.Context(), need.BoundConnectionID)
		}
		if err != nil || row.DisplayName != want {
			t.Fatalf("connection %s display name = %q, want %q (err=%v)", slug, row.DisplayName, want, err)
		}
	}
	assertConnectionName("token", "Token connection", false)
	assertConnectionName("oauth", "OAuth connection", true)

	for _, tc := range []struct {
		slug        string
		want        string
		provisional bool
	}{{"mcp-token", "Token MCP", false}, {"mcp-oauth", "OAuth MCP", true}} {
		need, err := q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(agentID), Type: "mcp_server", Slug: tc.slug})
		if err != nil {
			t.Fatal(err)
		}
		var row dbq.AgentMcpServer
		if tc.provisional {
			row, err = q.GetProvisionalMCPServerForNeedOwner(t.Context(), dbq.GetProvisionalMCPServerForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: pgUUID(owner)})
		} else {
			row, err = q.GetMCPServerByID(t.Context(), need.BoundMcpID)
		}
		if err != nil || row.DisplayName != tc.want {
			t.Fatalf("MCP %s display name = %q, want %q (err=%v)", tc.slug, row.DisplayName, tc.want, err)
		}
	}
	exec, err := q.ResolveBoundExecEndpoint(t.Context(), dbq.ResolveBoundExecEndpointParams{AgentID: pgUUID(agentID), Slug: "shell"})
	if err != nil || exec.DisplayName != "Shell" {
		t.Fatalf("exec display name = %q, want Shell (err=%v)", exec.DisplayName, err)
	}
	if resp := h.Do(h.NewRequest(http.MethodPost, "/api/v1/agents/"+agentID.String()+"/credentials/token", token, &airlockv1.SetAPIKeyRequest{ApiKey: "replacement"})); resp.StatusCode != http.StatusOK {
		t.Fatalf("blank display name for existing binding = %d, want 200", resp.StatusCode)
	}

	if resp := h.Do(h.NewRequest(http.MethodPost, "/api/v1/agents/"+agentID.String()+"/credentials/token", token, &airlockv1.SetAPIKeyRequest{ApiKey: "secret", CreateNew: true})); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("blank explicit create-new = %d, want 400", resp.StatusCode)
	}
}

func TestRuntimeRejectsInsufficientOAuthBinding(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "runtime-scope-owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	resourceID := seedOAuthConnection(t, h, agentID, "runtime", "read", "read")
	seedConnectionNeed(t, h, agentID, "runtime", "read write")
	q := dbq.New(h.DB.Pool())
	if _, err := q.BindConnectionNeed(context.Background(), dbq.BindConnectionNeedParams{AgentID: pgUUID(agentID), Slug: "runtime", ResourceID: pgUUID(resourceID)}); err != nil {
		t.Fatal(err)
	}
	_, err := q.ResolveBoundConnection(context.Background(), dbq.ResolveBoundConnectionParams{AgentID: pgUUID(agentID), Slug: "runtime"})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("runtime resolution error = %v, want no rows", err)
	}
}

func TestRuntimeRejectsUnverifiedOAuthBinding(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "runtime-unverified-owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	resourceID := seedOAuthConnection(t, h, agentID, "runtime-unverified", "read write", "read write")
	seedConnectionNeed(t, h, agentID, "runtime-unverified", "read write")
	q := dbq.New(h.DB.Pool())
	if _, err := q.BindConnectionNeed(t.Context(), dbq.BindConnectionNeedParams{AgentID: pgUUID(agentID), Slug: "runtime-unverified", ResourceID: pgUUID(resourceID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Pool().Exec(t.Context(), `UPDATE connections SET access_token_ref='', refresh_token='', scopes_verified=false WHERE id=$1`, pgUUID(resourceID)); err != nil {
		t.Fatal(err)
	}
	if _, err := q.ResolveBoundConnection(t.Context(), dbq.ResolveBoundConnectionParams{AgentID: pgUUID(agentID), Slug: "runtime-unverified"}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("runtime resolution error = %v, want no rows", err)
	}
}

func TestResourceAuthorizationRouterLifecycle(t *testing.T) {
	for _, createNew := range []bool{false, true} {
		name := "existing candidate"
		if createNew {
			name = "create-new provisional"
		}
		t.Run(name, func(t *testing.T) {
			h := apitest.Setup(t)
			owner := apitest.CreateUser(t, h, "router-oauth-owner", "user")
			token := apitest.IssueUserToken(t, h, owner, "router-oauth-owner@apitest.local", "user")
			agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
			var tokenRequests int
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/token" {
					http.NotFound(w, r)
					return
				}
				tokenRequests++
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "router-access", "refresh_token": "router-refresh", "scope": "read write",
				})
			}))
			t.Cleanup(provider.Close)

			q := dbq.New(h.DB.Pool())
			spec := []byte(`{"name":"Documents","base_url":"` + provider.URL + `","auth_mode":"oauth","auth_url":"` + provider.URL + `/authorize","token_url":"` + provider.URL + `/token","scopes":"read write","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`)
			if err := q.UpsertResourceNeed(t.Context(), dbq.UpsertResourceNeedParams{
				AgentID: pgUUID(agentID), Type: "connection", Slug: "documents", Description: "Documents",
				ExpectedUrl: provider.URL, ExpectedScopes: "read write", Spec: spec,
			}); err != nil {
				t.Fatal(err)
			}
			prior, err := q.UpsertConnection(t.Context(), dbq.UpsertConnectionParams{
				AgentID: pgUUID(agentID), Slug: "prior", Name: "Prior", DisplayName: "Prior",
				AuthMode: "oauth", AuthUrl: provider.URL + "/authorize", TokenUrl: provider.URL + "/token",
				BaseUrl: provider.URL, Scopes: "read write", AuthInjection: []byte(`{"type":"bearer"}`),
				Config: []byte("{}"), AuthParams: []byte("{}"), Headers: []byte("{}"),
			})
			if err != nil {
				t.Fatal(err)
			}
			priorID := uuid.UUID(prior.ID.Bytes)
			priorAccess, err := h.Secrets.Put(t.Context(), "connection/"+priorID.String()+"/access_token", "prior-access")
			if err != nil {
				t.Fatal(err)
			}
			if err := q.UpdateConnectionCredentialsByID(t.Context(), dbq.UpdateConnectionCredentialsByIDParams{
				ID: prior.ID, AccessTokenRef: priorAccess, GrantedScopes: "read write", ScopesVerified: true,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := q.BindConnectionNeed(t.Context(), dbq.BindConnectionNeedParams{AgentID: pgUUID(agentID), Slug: "documents", ResourceID: prior.ID}); err != nil {
				t.Fatal(err)
			}

			resourceID := priorID
			if createNew {
				path := "/api/v1/agents/" + agentID.String() + "/credentials/documents/oauth-app"
				resp := h.Do(h.NewRequest(http.MethodPut, path, token, &airlockv1.SetOAuthAppRequest{
					DisplayName: "Replacement", ClientId: "router-client", ClientSecret: "router-secret", CreateNew: true,
				}))
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("configure provisional: %d %s", resp.StatusCode, h.ReadBody(resp))
				}
				resp.Body.Close()
			} else {
				clientID, err := h.Secrets.Put(t.Context(), "connection/"+priorID.String()+"/client_id", "router-client")
				if err != nil {
					t.Fatal(err)
				}
				clientSecret, err := h.Secrets.Put(t.Context(), "connection/"+priorID.String()+"/client_secret", "router-secret")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := h.DB.Pool().Exec(t.Context(), `UPDATE connections SET client_id=$2, client_secret=$3 WHERE id=$1`, prior.ID, clientID, clientSecret); err != nil {
					t.Fatal(err)
				}
			}

			startReq := &airlockv1.StartAuthorizationForNeedRequest{
				AgentId: agentID.String(), Type: "connection", Slug: "documents", ResourceId: resourceID.String(),
				RedirectUri: "/agents/" + agentID.String() + "?tab=connections", CreateNew: createNew,
			}
			if createNew {
				startReq.ResourceId = ""
			}
			resp := h.Do(h.NewRequest(http.MethodPost, "/api/v1/resource-authorizations/start", token, startReq))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("start authorization: %d %s", resp.StatusCode, h.ReadBody(resp))
			}
			started := &airlockv1.StartAuthorizationForNeedResponse{}
			h.DecodeProto(resp, started)
			if started.Status != "authorization_started" || started.ResourceId == "" || started.AuthorizeUrl == "" {
				t.Fatalf("start response = %+v", started)
			}
			startedID := uuid.MustParse(started.ResourceId)
			if createNew && startedID == priorID {
				t.Fatal("create_new targeted the prior resource")
			}
			if !createNew && startedID != priorID {
				t.Fatalf("existing start resource = %s, want %s", startedID, priorID)
			}
			need, err := q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(agentID), Type: "connection", Slug: "documents"})
			if err != nil || uuid.UUID(need.BoundConnectionID.Bytes) != priorID {
				t.Fatalf("binding moved before callback: %+v err=%v", need, err)
			}
			if createNew {
				provisional, err := q.GetConnectionByID(t.Context(), pgUUID(startedID))
				if err != nil || provisional.Lifecycle != "provisional" {
					t.Fatalf("provisional = %+v err=%v", provisional, err)
				}
				for _, resource := range listResources(t, h, token).Resources {
					if resource.Id == started.ResourceId {
						t.Fatal("provisional resource leaked into inventory")
					}
				}
			}

			authorizeURL, err := url.Parse(started.AuthorizeUrl)
			if err != nil || authorizeURL.Query().Get("state") == "" || authorizeURL.Query().Get("scope") != "read write" {
				t.Fatalf("authorize URL = %q err=%v", started.AuthorizeUrl, err)
			}
			callback := h.NewRequest(http.MethodGet, "/api/v1/credentials/oauth/callback?code=router-code&state="+url.QueryEscape(authorizeURL.Query().Get("state")), "", nil)
			client := *h.Server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			callbackResp, err := client.Do(callback)
			if err != nil {
				t.Fatal(err)
			}
			callbackResp.Body.Close()
			if callbackResp.StatusCode != http.StatusFound {
				t.Fatalf("callback status = %d, want 302", callbackResp.StatusCode)
			}
			location, err := url.Parse(callbackResp.Header.Get("Location"))
			if err != nil || location.Query().Get("oauth_status") != "authorized" || location.Query().Get("resource_id") != started.ResourceId {
				t.Fatalf("callback location = %q err=%v", callbackResp.Header.Get("Location"), err)
			}
			need, err = q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: pgUUID(agentID), Type: "connection", Slug: "documents"})
			if err != nil || uuid.UUID(need.BoundConnectionID.Bytes) != startedID {
				t.Fatalf("callback binding = %+v err=%v, want %s", need, err, startedID)
			}
			active, err := q.GetConnectionByID(t.Context(), pgUUID(startedID))
			if err != nil || active.Lifecycle != "active" || active.GrantedScopes != "read write" || !active.ScopesVerified {
				t.Fatalf("activated resource = %+v err=%v", active, err)
			}
			if tokenRequests != 1 {
				t.Fatalf("token requests = %d, want 1", tokenRequests)
			}
			if createNew {
				old, err := q.GetConnectionByID(t.Context(), prior.ID)
				if err != nil || old.AccessTokenRef != priorAccess {
					t.Fatalf("prior resource changed: %+v err=%v", old, err)
				}
			}
		})
	}
}

func TestRuntimeScopeEnforcementThroughHTTPPaths(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "runtime-http-owner", "user")
	userToken := apitest.IssueUserToken(t, h, owner, "runtime-http-owner@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	agentToken := apitest.IssueAgentToken(t, h, agentID)
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != "Bearer runtime-token" {
			t.Errorf("Authorization = %q", got)
		}
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)

	q := dbq.New(h.DB.Pool())
	conn, err := q.UpsertConnection(t.Context(), dbq.UpsertConnectionParams{
		AgentID: pgUUID(agentID), Slug: "runtime-http", Name: "Runtime HTTP", DisplayName: "Runtime HTTP",
		AuthMode: "oauth", AuthUrl: upstream.URL + "/authorize", TokenUrl: upstream.URL + "/token", BaseUrl: upstream.URL,
		Scopes: "read", AuthInjection: []byte(`{"type":"bearer"}`), Config: []byte("{}"), AuthParams: []byte("{}"), Headers: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceID := uuid.UUID(conn.ID.Bytes)
	accessRef, err := h.Secrets.Put(t.Context(), "connection/"+resourceID.String()+"/access_token", "runtime-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.UpdateConnectionCredentialsByID(t.Context(), dbq.UpdateConnectionCredentialsByIDParams{
		ID: conn.ID, AccessTokenRef: accessRef, GrantedScopes: "read", ScopesVerified: true,
	}); err != nil {
		t.Fatal(err)
	}
	needParams := dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(agentID), Type: "connection", Slug: "runtime-http", Description: "Runtime HTTP",
		ExpectedUrl: upstream.URL, ExpectedScopes: "read",
		Spec: []byte(`{"name":"Runtime HTTP","base_url":"` + upstream.URL + `","auth_mode":"oauth","scopes":"read","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`),
	}
	if err := q.UpsertResourceNeed(t.Context(), needParams); err != nil {
		t.Fatal(err)
	}
	if _, err := q.BindConnectionNeed(t.Context(), dbq.BindConnectionNeedParams{AgentID: pgUUID(agentID), Slug: "runtime-http", ResourceID: conn.ID}); err != nil {
		t.Fatal(err)
	}

	agentPath := "/api/agent/proxy/runtime-http"
	integrationPath := "/api/v1/agents/" + agentID.String() + "/integrations/connections/runtime-http/request"
	agentResp := h.Do(h.NewRequest(http.MethodPost, agentPath, agentToken, []byte(`{"method":"GET","path":"/covered"}`)))
	if agentResp.StatusCode != http.StatusOK || string(h.ReadBody(agentResp)) != "upstream-ok" {
		t.Fatalf("covered agent proxy response = %d", agentResp.StatusCode)
	}
	integrationResp := h.Do(h.NewRequest(http.MethodPost, integrationPath, userToken, &airlockv1.InvokeConnectionRequest{Method: "GET", Path: "/covered"}))
	if integrationResp.StatusCode != http.StatusOK {
		t.Fatalf("covered integration response = %d %s", integrationResp.StatusCode, h.ReadBody(integrationResp))
	}
	integrationResp.Body.Close()
	if calls != 2 {
		t.Fatalf("covered upstream calls = %d, want 2", calls)
	}

	needParams.ExpectedScopes = "read write"
	needParams.Spec = []byte(`{"name":"Runtime HTTP","base_url":"` + upstream.URL + `","auth_mode":"oauth","scopes":"read write","auth_injection":{"type":"bearer"},"auth_params":{},"headers":{}}`)
	if err := q.UpsertResourceNeed(t.Context(), needParams); err != nil {
		t.Fatal(err)
	}
	agentResp = h.Do(h.NewRequest(http.MethodPost, agentPath, agentToken, []byte(`{"method":"GET","path":"/blocked"}`)))
	if agentResp.StatusCode != http.StatusNotFound || !strings.Contains(string(h.ReadBody(agentResp)), "connection not bound") {
		t.Fatalf("underscoped agent proxy status = %d", agentResp.StatusCode)
	}
	integrationResp = h.Do(h.NewRequest(http.MethodPost, integrationPath, userToken, &airlockv1.InvokeConnectionRequest{Method: "GET", Path: "/blocked"}))
	if integrationResp.StatusCode != http.StatusNotFound || !strings.Contains(string(h.ReadBody(integrationResp)), "is not bound") {
		t.Fatalf("underscoped integration status = %d", integrationResp.StatusCode)
	}
	if calls != 2 {
		t.Fatalf("underscoped requests reached upstream: calls=%d", calls)
	}
}

func TestRuntimeMCPScopeEnforcementThroughAgentHandler(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "runtime-mcp-owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	agentToken := apitest.IssueAgentToken(t, h, agentID)
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer runtime-mcp-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode MCP request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(mcp.HeaderSessionID, "runtime-session")
		if request.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		results := map[string]any{
			"initialize":     map[string]any{"protocolVersion": "2025-06-18"},
			"tools/list":     map[string]any{"tools": []map[string]any{{"name": "lookup", "inputSchema": map[string]any{"type": "object"}}}},
			"resources/list": map[string]any{"resources": []any{}},
			"tools/call":     map[string]any{"content": []map[string]any{{"type": "text", "text": "mcp-ok"}}},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": results[request.Method]})
	}))
	t.Cleanup(upstream.Close)

	q := dbq.New(h.DB.Pool())
	server, err := q.UpsertMCPServer(t.Context(), dbq.UpsertMCPServerParams{
		AgentID: pgUUID(agentID), Slug: "runtime-mcp", Name: "Runtime MCP", DisplayName: "Runtime MCP",
		Url: upstream.URL, AuthMode: "oauth", AuthUrl: upstream.URL + "/authorize", TokenUrl: upstream.URL + "/token",
		Scopes: "read", Access: "admin", AuthInjection: []byte(`{"type":"bearer"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverID := uuid.UUID(server.ID.Bytes)
	accessRef, err := h.Secrets.Put(t.Context(), "mcp/"+serverID.String()+"/access_token", "runtime-mcp-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.UpdateMCPServerCredentialsByID(t.Context(), dbq.UpdateMCPServerCredentialsByIDParams{
		ID: server.ID, AccessTokenRef: accessRef, GrantedScopes: "read", ScopesVerified: true,
	}); err != nil {
		t.Fatal(err)
	}
	need := dbq.UpsertResourceNeedParams{
		AgentID: pgUUID(agentID), Type: "mcp_server", Slug: "runtime-mcp", Description: "Runtime MCP",
		ExpectedUrl: upstream.URL, ExpectedScopes: "read",
		Spec: []byte(`{"name":"Runtime MCP","url":"` + upstream.URL + `","auth_mode":"oauth","scopes":"read","auth_injection":{"type":"bearer"}}`),
	}
	if err := q.UpsertResourceNeed(t.Context(), need); err != nil {
		t.Fatal(err)
	}
	if _, err := q.BindMCPServerNeed(t.Context(), dbq.BindMCPServerNeedParams{AgentID: pgUUID(agentID), Slug: "runtime-mcp", ResourceID: server.ID}); err != nil {
		t.Fatal(err)
	}
	path := "/api/agent/mcp/runtime-mcp/tools/call"
	body := []byte(`{"tool":"lookup","arguments":{"query":"airlock"}}`)
	resp := h.Do(h.NewRequest(http.MethodPost, path, agentToken, body))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(h.ReadBody(resp)), "mcp-ok") {
		t.Fatalf("covered MCP status = %d", resp.StatusCode)
	}
	coveredCalls := calls
	if coveredCalls == 0 {
		t.Fatal("covered MCP call did not reach upstream")
	}

	need.ExpectedScopes = "read write"
	need.Spec = []byte(`{"name":"Runtime MCP","url":"` + upstream.URL + `","auth_mode":"oauth","scopes":"read write","auth_injection":{"type":"bearer"}}`)
	if err := q.UpsertResourceNeed(t.Context(), need); err != nil {
		t.Fatal(err)
	}
	resp = h.Do(h.NewRequest(http.MethodPost, path, agentToken, body))
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(h.ReadBody(resp)), "MCP server not bound") {
		t.Fatalf("underscoped MCP status = %d", resp.StatusCode)
	}
	if calls != coveredCalls {
		t.Fatalf("underscoped MCP reached upstream: before=%d after=%d", coveredCalls, calls)
	}
}

func TestResourceGrantMutationAPI(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "grant-api-owner", "user")
	delegate := apitest.CreateUser(t, h, "grant-api-delegate", "user")
	viewer := apitest.CreateUser(t, h, "grant-api-viewer", "user")
	ownerToken := apitest.IssueUserToken(t, h, owner, "grant-api-owner@apitest.local", "user")
	delegateToken := apitest.IssueUserToken(t, h, delegate, "grant-api-delegate@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	firstID := seedConnection(t, h, agentID, "grant-first", false)
	secondID := seedConnection(t, h, agentID, "grant-second", false)
	path := "/api/v1/resources/connection/" + firstID.String() + "/grants"
	grant := func(token string, grantee uuid.UUID, caps ...string) int {
		resp := h.Do(h.NewRequest(http.MethodPost, path, token, &airlockv1.GrantResourceRequest{GranteeId: grantee.String(), Capabilities: caps}))
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := grant(ownerToken, viewer, "invalid"); got != http.StatusBadRequest {
		t.Fatalf("invalid capability status = %d, want 400", got)
	}
	if got := grant(ownerToken, delegate, "manage"); got != http.StatusNoContent {
		t.Fatalf("delegate manage create = %d", got)
	}
	if got := grant(ownerToken, authz.GroupUser, "view"); got != http.StatusNoContent {
		t.Fatalf("group grant create = %d", got)
	}
	if got := grant(ownerToken, authz.GroupUser, "view", "bind"); got != http.StatusNoContent {
		t.Fatalf("group grant update = %d", got)
	}
	if got := grant(delegateToken, viewer, "view", "bind"); got != http.StatusNoContent {
		t.Fatalf("delegated grant create = %d", got)
	}
	if got := grant(delegateToken, viewer, "manage"); got != http.StatusNoContent {
		t.Fatalf("delegated grant update = %d", got)
	}

	resp := h.Do(h.NewRequest(http.MethodGet, path, delegateToken, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delegated list = %d %s", resp.StatusCode, h.ReadBody(resp))
	}
	listed := &airlockv1.ListResourceGrantsResponse{}
	h.DecodeProto(resp, listed)
	if len(listed.Grants) != 3 {
		t.Fatalf("listed grants = %+v", listed.Grants)
	}
	var viewerGrantID, groupGrantID string
	for _, item := range listed.Grants {
		if item.GranteeId == viewer.String() {
			viewerGrantID = item.Id
			if len(item.Capabilities) != 1 || item.Capabilities[0] != "manage" {
				t.Fatalf("updated viewer grant = %+v", item)
			}
		}
		if item.GranteeId == authz.GroupUser.String() {
			groupGrantID = item.Id
			if len(item.Capabilities) != 2 || item.Capabilities[0] != "view" || item.Capabilities[1] != "bind" {
				t.Fatalf("updated group grant = %+v", item)
			}
		}
	}
	if viewerGrantID == "" || groupGrantID == "" {
		t.Fatalf("grant IDs not listed: viewer=%q group=%q", viewerGrantID, groupGrantID)
	}
	wrongPath := "/api/v1/resources/connection/" + secondID.String() + "/grants/" + viewerGrantID
	wrong := h.Do(h.NewRequest(http.MethodDelete, wrongPath, ownerToken, nil))
	wrong.Body.Close()
	if wrong.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong-resource revoke = %d, want 404", wrong.StatusCode)
	}
	remove := h.Do(h.NewRequest(http.MethodDelete, path+"/"+viewerGrantID, delegateToken, nil))
	remove.Body.Close()
	if remove.StatusCode != http.StatusNoContent {
		t.Fatalf("delegated revoke = %d, want 204", remove.StatusCode)
	}
	remove = h.Do(h.NewRequest(http.MethodDelete, path+"/"+groupGrantID, delegateToken, nil))
	remove.Body.Close()
	if remove.StatusCode != http.StatusNoContent {
		t.Fatalf("delegated group revoke = %d, want 204", remove.StatusCode)
	}
}

func TestAgentUserCannotMutateNeedsDespiteResourceGrants(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "need-gate-owner", "user")
	member := apitest.CreateUser(t, h, "need-gate-member", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	apitest.AddAgentMember(t, h, agentID, member, "user")
	memberToken := apitest.IssueUserToken(t, h, member, "need-gate-member@apitest.local", "user")
	resourceID := seedOAuthConnection(t, h, agentID, "need-gate-resource", "read", "read")
	seedConnectionNeed(t, h, agentID, "need-gate", "read")
	q := dbq.New(h.DB.Pool())
	if _, err := q.CreateConnectionGrant(t.Context(), dbq.CreateConnectionGrantParams{
		ConnectionID: pgUUID(resourceID), GranteeID: pgUUID(member), Capabilities: []string{"view", "bind", "manage"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.BindConnectionNeed(t.Context(), dbq.BindConnectionNeedParams{AgentID: pgUUID(agentID), Slug: "need-gate", ResourceID: pgUUID(resourceID)}); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/agents/" + agentID.String() + "/needs/connection/need-gate"
	tests := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{name: "create", method: http.MethodPost, path: base + "/create", body: &airlockv1.CreateForNeedRequest{DisplayName: "Denied"}},
		{name: "bind", method: http.MethodPost, path: base + "/bind", body: &airlockv1.BindNeedRequest{ResourceId: resourceID.String()}},
		{name: "unbind", method: http.MethodDelete, path: base + "/bind"},
		{name: "authorization start", method: http.MethodPost, path: "/api/v1/resource-authorizations/start", body: &airlockv1.StartAuthorizationForNeedRequest{
			AgentId: agentID.String(), Type: "connection", Slug: "need-gate", ResourceId: resourceID.String(),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.Do(h.NewRequest(tc.method, tc.path, memberToken, tc.body))
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
		})
	}
}
