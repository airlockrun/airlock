package apitest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestIntegrationAccess_UserAndCodegen(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "owner", "user")
	member := apitest.CreateUser(t, h, "member", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	apitest.AddAgentMember(t, h, agentID, member, "user")

	ownerToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")
	memberToken := apitest.IssueUserToken(t, h, member, "member@apitest.local", "user")
	path := "/api/v1/agents/" + agentID.String() + "/integrations/"

	resp := h.Do(h.NewRequest(http.MethodGet, path, ownerToken, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner integration list status = %d, body=%s", resp.StatusCode, h.ReadBody(resp))
	}
	var listed airlockv1.ListIntegrationsResponse
	h.DecodeProto(resp, &listed)

	resp = h.Do(h.NewRequest(http.MethodGet, path, memberToken, nil))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member integration list status = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	oauthToken, err := auth.IssueOAuthAccessToken(h.JWTSecret, owner, "owner@apitest.local", "user", "client", "mcp", "https://example.com/mcp", 0)
	if err != nil {
		t.Fatalf("IssueOAuthAccessToken() error: %v", err)
	}
	resp = h.Do(h.NewRequest(http.MethodGet, path, oauthToken, nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("MCP OAuth token integration status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	q := dbq.New(h.DB.Pool())
	build, err := q.CreateAgentBuild(context.Background(), dbq.CreateAgentBuildParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true}, Type: "upgrade", Instructions: "configured",
	})
	if err != nil {
		t.Fatalf("CreateAgentBuild() error: %v", err)
	}
	codegenToken, tokenHash, err := auth.NewIntegrationToken()
	if err != nil {
		t.Fatalf("NewIntegrationToken() error: %v", err)
	}
	rows, err := q.SetAgentBuildIntegrationToken(context.Background(), dbq.SetAgentBuildIntegrationTokenParams{
		ID: build.ID, IntegrationTokenHash: tokenHash,
		IntegrationTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Minute), Valid: true},
	})
	if err != nil || rows != 1 {
		t.Fatalf("SetAgentBuildIntegrationToken() = (%d, %v), want (1, nil)", rows, err)
	}

	resp = h.Do(h.NewRequest(http.MethodGet, "/api/codegen/integrations/", codegenToken, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("codegen integration list status = %d, body=%s", resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()

	resp = h.Do(h.NewRequest(http.MethodGet, "/api/v1/agents/"+agentID.String()+"/source", codegenToken, nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("codegen token source status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	if err := q.ClearAgentBuildIntegrationToken(context.Background(), build.ID); err != nil {
		t.Fatalf("ClearAgentBuildIntegrationToken() error: %v", err)
	}
	resp = h.Do(h.NewRequest(http.MethodGet, "/api/codegen/integrations/", codegenToken, nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked codegen token status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}
