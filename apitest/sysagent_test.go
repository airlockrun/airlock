package apitest_test

import (
	"net/http"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

// TestIntegration_SystemConversations_CRUD covers the per-user
// sysagent conversation surface end to end: an authenticated user can
// list (empty), create, list (one), get, then delete. No prompt is
// fired in this test — that would need a configured LLM provider; the
// CRUD surface is testable on its own.
func TestIntegration_SystemConversations_CRUD(t *testing.T) {
	h := apitest.Setup(t)

	userID := apitest.CreateUser(t, h, "sysop", "user")
	token := apitest.IssueUserToken(t, h, userID, "sysop@apitest.local", "user")

	// 1. Empty list — fresh user has no conversations.
	req := h.NewRequest(http.MethodGet, "/api/v1/system/conversations", token, nil)
	resp := h.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list (empty) = %d, want 200; body=%s", resp.StatusCode, h.ReadBody(resp))
	}
	var list airlockv1.ListSystemConversationsResponse
	h.DecodeProto(resp, &list)
	if len(list.Conversations) != 0 {
		t.Fatalf("expected empty list, got %d conversations", len(list.Conversations))
	}

	// 2. Create — server defaults title to "New chat" when blank.
	createReq := &airlockv1.CreateSystemConversationRequest{}
	req = h.NewRequest(http.MethodPost, "/api/v1/system/conversations", token, createReq)
	resp = h.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d, want 201; body=%s", resp.StatusCode, h.ReadBody(resp))
	}
	var created airlockv1.CreateSystemConversationResponse
	h.DecodeProto(resp, &created)
	if created.Conversation == nil || created.Conversation.Id == "" {
		t.Fatalf("create returned no conversation: %+v", created)
	}
	if created.Conversation.Title != "New chat" {
		t.Errorf("default title = %q, want %q", created.Conversation.Title, "New chat")
	}
	if created.Conversation.Status != "active" {
		t.Errorf("fresh conversation status = %q, want active", created.Conversation.Status)
	}
	convID := created.Conversation.Id

	// 3. List — one row, the conversation just created.
	req = h.NewRequest(http.MethodGet, "/api/v1/system/conversations", token, nil)
	resp = h.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list (after create) = %d, want 200", resp.StatusCode)
	}
	var list2 airlockv1.ListSystemConversationsResponse
	h.DecodeProto(resp, &list2)
	if len(list2.Conversations) != 1 || list2.Conversations[0].Id != convID {
		t.Fatalf("expected one conversation %q, got %+v", convID, list2.Conversations)
	}

	// 4. Get — returns the conversation + an empty messages slice (no
	//    prompts fired yet).
	req = h.NewRequest(http.MethodGet, "/api/v1/system/conversations/"+convID, token, nil)
	resp = h.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get = %d, want 200", resp.StatusCode)
	}
	var detail airlockv1.GetSystemConversationResponse
	h.DecodeProto(resp, &detail)
	if detail.Conversation == nil || detail.Conversation.Id != convID {
		t.Fatalf("get returned wrong conversation: %+v", detail.Conversation)
	}
	if len(detail.Messages) != 0 {
		t.Errorf("fresh conversation should have no messages, got %d", len(detail.Messages))
	}

	// 5. Delete — 204, then a second get returns 404 (ownership-scoped).
	req = h.NewRequest(http.MethodDelete, "/api/v1/system/conversations/"+convID, token, nil)
	resp = h.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", resp.StatusCode)
	}
	req = h.NewRequest(http.MethodGet, "/api/v1/system/conversations/"+convID, token, nil)
	resp = h.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404", resp.StatusCode)
	}
}

// TestIntegration_SystemConversations_OwnershipIsolation verifies that
// a second user can't see or touch the first user's sysagent
// conversation. Non-owner access returns 404 (not 403) — exposing
// existence to non-owners would leak metadata about other users'
// operator chats.
func TestIntegration_SystemConversations_OwnershipIsolation(t *testing.T) {
	h := apitest.Setup(t)

	alice := apitest.CreateUser(t, h, "alice", "user")
	bob := apitest.CreateUser(t, h, "bob", "user")
	aliceTok := apitest.IssueUserToken(t, h, alice, "alice@apitest.local", "user")
	bobTok := apitest.IssueUserToken(t, h, bob, "bob@apitest.local", "user")

	// Alice creates a conversation.
	createReq := &airlockv1.CreateSystemConversationRequest{Title: "alice's private"}
	req := h.NewRequest(http.MethodPost, "/api/v1/system/conversations", aliceTok, createReq)
	resp := h.Do(req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("alice create = %d, want 201", resp.StatusCode)
	}
	var created airlockv1.CreateSystemConversationResponse
	h.DecodeProto(resp, &created)
	convID := created.Conversation.Id

	// Bob lists — sees nothing.
	req = h.NewRequest(http.MethodGet, "/api/v1/system/conversations", bobTok, nil)
	resp = h.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob list = %d, want 200", resp.StatusCode)
	}
	var bobList airlockv1.ListSystemConversationsResponse
	h.DecodeProto(resp, &bobList)
	if len(bobList.Conversations) != 0 {
		t.Fatalf("bob should not see alice's conversations; got %d", len(bobList.Conversations))
	}

	// Bob tries to get alice's conversation by id — 404.
	req = h.NewRequest(http.MethodGet, "/api/v1/system/conversations/"+convID, bobTok, nil)
	resp = h.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bob get alice's conv = %d, want 404 (must not leak existence)", resp.StatusCode)
	}

	// Bob tries to delete it — also 404.
	req = h.NewRequest(http.MethodDelete, "/api/v1/system/conversations/"+convID, bobTok, nil)
	resp = h.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bob delete alice's conv = %d, want 404", resp.StatusCode)
	}

	// Alice's conversation still exists.
	req = h.NewRequest(http.MethodGet, "/api/v1/system/conversations/"+convID, aliceTok, nil)
	resp = h.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice get her own conv after bob's failed attempts = %d, want 200", resp.StatusCode)
	}
}

// TestIntegration_SystemConversations_UnauthenticatedRejected verifies
// the JWT middleware actually fires on /system/conversations. Without a
// Bearer token every method returns 401.
func TestIntegration_SystemConversations_UnauthenticatedRejected(t *testing.T) {
	h := apitest.Setup(t)

	methods := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/system/conversations", nil},
		{http.MethodPost, "/api/v1/system/conversations", &airlockv1.CreateSystemConversationRequest{}},
		{http.MethodGet, "/api/v1/system/runs", nil},
	}
	for _, tt := range methods {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := h.NewRequest(tt.method, tt.path, "", tt.body)
			resp := h.Do(req)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s = %d, want 401", tt.method, tt.path, resp.StatusCode)
			}
		})
	}
}

// TestIntegration_SystemRuns_EmptyAndIsolated verifies the activity
// endpoint: a fresh user sees an empty list, and the response shape
// includes runs + next_cursor (empty when no more pages exist).
func TestIntegration_SystemRuns_EmptyAndIsolated(t *testing.T) {
	h := apitest.Setup(t)

	userID := apitest.CreateUser(t, h, "runner", "user")
	token := apitest.IssueUserToken(t, h, userID, "runner@apitest.local", "user")

	req := h.NewRequest(http.MethodGet, "/api/v1/system/runs", token, nil)
	resp := h.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list runs = %d, want 200; body=%s", resp.StatusCode, h.ReadBody(resp))
	}
	var runs airlockv1.ListSystemRunsResponse
	h.DecodeProto(resp, &runs)
	if len(runs.Runs) != 0 {
		t.Errorf("fresh user should have no runs, got %d", len(runs.Runs))
	}
	if runs.NextCursor != "" {
		t.Errorf("empty page should not carry a cursor; got %q", runs.NextCursor)
	}
}

// TestIntegration_SystemRuns_BadCursorRejected — the handler parses
// the cursor as RFC3339; garbage input returns 400 (not 500). Keeps
// the operator's UI from hard-failing on a malformed bookmark.
func TestIntegration_SystemRuns_BadCursorRejected(t *testing.T) {
	h := apitest.Setup(t)

	userID := apitest.CreateUser(t, h, "runner", "user")
	token := apitest.IssueUserToken(t, h, userID, "runner@apitest.local", "user")

	req := h.NewRequest(http.MethodGet, "/api/v1/system/runs?cursor=not-a-date", token, nil)
	resp := h.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad cursor = %d, want 400", resp.StatusCode)
	}
}

// TestIntegration_SystemConversation_BadIDRejected verifies path-param
// validation: a non-UUID conversation id is 400, not 500 or 404. Keeps
// the surface honest about what malformed input looks like.
func TestIntegration_SystemConversation_BadIDRejected(t *testing.T) {
	h := apitest.Setup(t)

	userID := apitest.CreateUser(t, h, "u", "user")
	token := apitest.IssueUserToken(t, h, userID, "u@apitest.local", "user")

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req := h.NewRequest(method, "/api/v1/system/conversations/not-a-uuid", token, nil)
		resp := h.Do(req)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s bad id = %d, want 400", method, resp.StatusCode)
		}
	}
}
