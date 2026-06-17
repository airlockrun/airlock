package apitest_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
)

// seedConnection creates a token connection owned by the agent's user, declares
// a need for it, and binds it (so agent_count = 1). With withToken it reads as
// authorized. Returns the connection id.
func seedConnection(t *testing.T, h *apitest.Harness, agentID uuid.UUID, slug string, withToken bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	q := dbq.New(h.DB.Pool())
	conn, err := q.UpsertConnection(ctx, dbq.UpsertConnectionParams{
		AgentID: pgUUID(agentID), Slug: slug, Name: "Conn " + slug, AuthMode: "token",
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
	if err := q.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{
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

// TestResources_OwnerScoped: the inventory shows only the caller's own
// resources, with the agent-bind count, and never another user's.
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

// TestResources_RevokeGating: only the owner may clear a resource's credentials.
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

// TestResources_DeleteGating: only the owner may delete; the deleted resource's
// binding need is unbound (not deleted), so the agent falls back to setup.
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
