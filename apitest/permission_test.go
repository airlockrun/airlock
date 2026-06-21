package apitest_test

import (
	"net/http"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/authz"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
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

// TestIntegration_ShareWithEveryone verifies the "All users" share: granting
// the built-in `user` group (GroupUser) lifts every registered non-member from
// AccessPublic to AccessUser — they see the agent in their list and can read
// member-level resources — and removing the grant reverts that. The grant also
// surfaces as a group-kind row on the members list.
func TestIntegration_ShareWithEveryone(t *testing.T) {
	h := apitest.Setup(t)

	owner := apitest.CreateUser(t, h, "shareowner", "user")
	stranger := apitest.CreateUser(t, h, "sharestranger", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})

	ownerTok := apitest.IssueUserToken(t, h, owner, "shareowner@apitest.local", "user")
	strangerTok := apitest.IssueUserToken(t, h, stranger, "sharestranger@apitest.local", "user")

	base := "/api/v1/agents/" + agentID.String()
	status := func(method, token, path string, body any) int {
		req := h.NewRequest(method, base+path, token, body)
		resp := h.Do(req)
		resp.Body.Close()
		return resp.StatusCode
	}
	// listAccess returns ("", false) when the agent isn't in the caller's list,
	// else the caller's your_access on it.
	listAccess := func(token string) (string, bool) {
		req := h.NewRequest(http.MethodGet, "/api/v1/agents", token, nil)
		resp := h.Do(req)
		var out airlockv1.ListAgentsResponse
		h.DecodeProto(resp, &out)
		for _, a := range out.GetAgents() {
			if a.GetId() == agentID.String() {
				return a.GetYourAccess(), true
			}
		}
		return "", false
	}

	// Before sharing: the stranger is a non-member — refused, and the agent is
	// absent from their list.
	if got := status(http.MethodGet, strangerTok, "/members", nil); got != http.StatusForbidden {
		t.Fatalf("pre-share stranger GET /members = %d, want 403", got)
	}
	if _, ok := listAccess(strangerTok); ok {
		t.Fatal("pre-share: stranger should not see the agent in their list")
	}

	// Owner shares with everyone by granting the built-in `user` group.
	shareBody := &airlockv1.AddAgentMemberRequest{UserId: authz.GroupUser.String(), Role: "user"}
	if got := status(http.MethodPost, ownerTok, "/members", shareBody); got != http.StatusNoContent {
		t.Fatalf("share POST /members = %d, want 204", got)
	}

	// Now the stranger has AccessUser: reads member-level resources and sees the
	// agent in their list with your_access=user.
	if got := status(http.MethodGet, strangerTok, "/members", nil); got != http.StatusOK {
		t.Fatalf("post-share stranger GET /members = %d, want 200", got)
	}
	if access, ok := listAccess(strangerTok); !ok || access != "user" {
		t.Fatalf("post-share stranger list access = (%q, %v), want (\"user\", true)", access, ok)
	}

	// The grant shows on the members list as a group-kind row.
	membersReq := h.NewRequest(http.MethodGet, base+"/members", ownerTok, nil)
	var members airlockv1.ListAgentMembersResponse
	h.DecodeProto(h.Do(membersReq), &members)
	var foundGroup bool
	for _, m := range members.GetMembers() {
		if m.GetUserId() == authz.GroupUser.String() {
			foundGroup = true
			if m.GetKind() != "group" {
				t.Errorf("All-users member kind = %q, want \"group\"", m.GetKind())
			}
		}
	}
	if !foundGroup {
		t.Error("members list missing the All-users (GroupUser) grant")
	}

	// Removing the share reverts the stranger to non-member.
	if got := status(http.MethodDelete, ownerTok, "/members/"+authz.GroupUser.String(), nil); got != http.StatusNoContent {
		t.Fatalf("unshare DELETE = %d, want 204", got)
	}
	if got := status(http.MethodGet, strangerTok, "/members", nil); got != http.StatusForbidden {
		t.Fatalf("post-unshare stranger GET /members = %d, want 403", got)
	}
	if _, ok := listAccess(strangerTok); ok {
		t.Fatal("post-unshare: stranger should no longer see the agent")
	}
}
