package apitest_test

import (
	"net/http"
	"testing"

	"github.com/airlockrun/airlock/apitest"
)

// TestIntegration_AgentEndpointGates verifies the per-agent access ladder
// on the agent-scoped read endpoints: a non-member is refused everywhere,
// a plain 'user' member can read member-level resources but not the
// admin-only ones, and the owner (admin) can read everything.
func TestIntegration_AgentEndpointGates(t *testing.T) {
	h := apitest.Setup(t)

	owner := apitest.CreateUser(t, h, "owner", "user")
	member := apitest.CreateUser(t, h, "member", "user")
	stranger := apitest.CreateUser(t, h, "stranger", "user")

	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	apitest.AddAgentMember(t, h, agentID, member, "user")

	ownerTok := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")
	memberTok := apitest.IssueUserToken(t, h, member, "member@apitest.local", "user")
	strangerTok := apitest.IssueUserToken(t, h, stranger, "stranger@apitest.local", "user")

	base := "/api/v1/agents/" + agentID.String()
	get := func(token, path string) int {
		req := h.NewRequest(http.MethodGet, base+path, token, nil)
		resp := h.Do(req)
		resp.Body.Close()
		return resp.StatusCode
	}

	tests := []struct {
		name  string
		path  string
		owner int // admin
		mem   int // 'user' member
		stra  int // non-member
	}{
		// member-level reads: members may read, non-members are refused.
		{"members", "/members", http.StatusOK, http.StatusOK, http.StatusForbidden},
		{"runs", "/runs", http.StatusOK, http.StatusOK, http.StatusForbidden},
		{"tools", "/tools", http.StatusOK, http.StatusOK, http.StatusForbidden},
		{"builds", "/builds", http.StatusOK, http.StatusOK, http.StatusForbidden},
		// admin-only reads: even a 'user' member is refused.
		{"webhooks", "/webhooks", http.StatusOK, http.StatusForbidden, http.StatusForbidden},
		{"schedules", "/schedules", http.StatusOK, http.StatusForbidden, http.StatusForbidden},
		{"exec-endpoints", "/exec-endpoints", http.StatusOK, http.StatusForbidden, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := get(ownerTok, tt.path); got != tt.owner {
				t.Errorf("owner GET %s = %d, want %d", tt.path, got, tt.owner)
			}
			if got := get(memberTok, tt.path); got != tt.mem {
				t.Errorf("member GET %s = %d, want %d", tt.path, got, tt.mem)
			}
			if got := get(strangerTok, tt.path); got != tt.stra {
				t.Errorf("stranger GET %s = %d, want %d", tt.path, got, tt.stra)
			}
		})
	}
}
