package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/trigger"
	"github.com/airlockrun/sol/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// testConversation creates an agent, user, and conversation — returning the conv UUID.
func testConversation(t *testing.T, agentID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	q := dbq.New(testDB.Pool())

	conv, err := q.GetOrCreateConversation(ctx, dbq.GetOrCreateConversationParams{
		AgentID: toPgUUID(agentID),
		UserID:  toPgUUID(userID),
		Source:  "web",
		Title:   "test",
	})
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	return pgUUID(conv.ID)
}

// TestSessionCompact_InsertsMarkerAndAdvancesCheckpoint verifies that after
// SessionCompact:
// 1. A checkpoint-marker message exists with source='checkpoint'.
// 2. Summary messages are inserted.
// 3. The conversation's context_checkpoint_message_id points at the first
//    summary row.
// 4. Pre-existing messages remain in the DB.
// 5. ListSessionMessagesByConversation returns only post-checkpoint summary
//    messages (filtering out both pre-checkpoint history and the marker row).
func TestSessionCompact_InsertsMarkerAndAdvancesCheckpoint(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)

	ctx := context.Background()
	q := dbq.New(testDB.Pool())

	// Insert some pre-existing messages to simulate prior conversation.
	for _, role := range []string{"user", "assistant", "user"} {
		_, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
			ConversationID: toPgUUID(convID),
			Role:           role,
			Content:        role + " pre-compaction",
			Source:         "user",
		})
		if err != nil {
			t.Fatalf("CreateMessage: %v", err)
		}
	}

	router := testRouter(ah, func(r chi.Router) {
		r.Post("/api/agent/session/{convID}/compact", ah.SessionCompact)
	})

	summary := []session.Message{
		{Role: "user", Content: "original user message"},
		{Role: "assistant", Content: "summary of prior conversation", Summary: true},
		{Role: "user", Content: "Continue if you have next steps"},
	}
	req := agentRequest(t, "POST", "/api/agent/session/"+convID.String()+"/compact", agentID, map[string]any{
		"summary":     summary,
		"tokensFreed": 12345,
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", rec.Code, rec.Body.String())
	}

	// All messages stay in DB.
	allMsgs, err := q.ListAllMessagesByConversation(ctx, toPgUUID(convID))
	if err != nil {
		t.Fatalf("ListAllMessagesByConversation: %v", err)
	}
	// 3 pre + 1 marker + 3 summary = 7
	if len(allMsgs) != 7 {
		t.Errorf("all messages = %d, want 7", len(allMsgs))
	}

	// One checkpoint-marker row exists with embedded tokensFreed metadata.
	var markerCount int
	var markerFound bool
	for _, m := range allMsgs {
		if m.Source == "checkpoint" {
			markerCount++
			markerFound = true
			var parts []map[string]any
			if err := json.Unmarshal(m.Parts, &parts); err != nil {
				t.Fatalf("decode marker parts: %v", err)
			}
			if len(parts) != 1 {
				t.Fatalf("marker parts len = %d, want 1", len(parts))
			}
			if parts[0]["kind"] != "compact" {
				t.Errorf("marker kind = %v, want compact", parts[0]["kind"])
			}
			// JSON numbers decode as float64.
			if parts[0]["tokensFreed"].(float64) != 12345 {
				t.Errorf("marker tokensFreed = %v, want 12345", parts[0]["tokensFreed"])
			}
		}
	}
	if !markerFound {
		t.Fatal("no checkpoint marker message inserted")
	}
	if markerCount != 1 {
		t.Errorf("marker count = %d, want 1", markerCount)
	}

	// Checkpoint pointer is set.
	conv, err := q.GetConversationByID(ctx, toPgUUID(convID))
	if err != nil {
		t.Fatalf("GetConversationByID: %v", err)
	}
	if !conv.ContextCheckpointMessageID.Valid {
		t.Fatal("context_checkpoint_message_id not set after compact")
	}

	// Session (LLM-facing) listing returns only the 3 summary messages —
	// marker is filtered by source, pre-compaction by created_at.
	sessionMsgs, err := q.ListSessionMessagesByConversation(ctx, toPgUUID(convID))
	if err != nil {
		t.Fatalf("ListSessionMessagesByConversation: %v", err)
	}
	if len(sessionMsgs) != 3 {
		t.Fatalf("session messages = %d, want 3 (just the summary)", len(sessionMsgs))
	}
	if sessionMsgs[0].Content != "original user message" {
		t.Errorf("first session message content = %q, want 'original user message'", sessionMsgs[0].Content)
	}
}

// TestSessionCompact_EmptySummaryRejected verifies the handler rejects an
// empty summary — compacting with nothing to carry forward is never intended.
func TestSessionCompact_EmptySummaryRejected(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)

	router := testRouter(ah, func(r chi.Router) {
		r.Post("/api/agent/session/{convID}/compact", ah.SessionCompact)
	})

	req := agentRequest(t, "POST", "/api/agent/session/"+convID.String()+"/compact", agentID, map[string]any{
		"summary":     []session.Message{},
		"tokensFreed": 0,
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// TestClearCommand_ResolvesSuspendedRun verifies that /clear not only
// advances the checkpoint but also resolves any in-flight suspended run.
// Leaving the run suspended would cause GetConversation to keep returning a
// pending-confirmation after the user explicitly said "forget it."
func TestClearCommand_ResolvesSuspendedRun(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)

	ctx := context.Background()
	q := dbq.New(testDB.Pool())

	// Insert a suspended run for this agent — the state /clear should resolve.
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID:       toPgUUID(agentID),
		InputPayload:  []byte("{}"),
		SourceRef:     "",
		TriggerType:   "prompt",
		TriggerRef:    "",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if _, err := testDB.Pool().Exec(ctx, `UPDATE runs SET status='suspended' WHERE id=$1`, run.ID); err != nil {
		t.Fatalf("mark suspended: %v", err)
	}

	// Dispatch /clear via the shared slash-command helper.
	res, err := trigger.TrySlashCommand(ctx, q, toPgUUID(convID), agentID, agentsdk.AccessUser, "/clear", zap.NewNop())
	if err != nil {
		t.Fatalf("TrySlashCommand: %v", err)
	}
	if !res.Handled {
		t.Fatal("expected Handled=true")
	}
	if !strings.Contains(res.Reply, "Pending confirmation cancelled") {
		t.Errorf("reply = %q, want the suspended-run note appended", res.Reply)
	}

	got, err := q.GetRunByID(ctx, run.ID)
	if err != nil {
		t.Fatalf("GetRunByID: %v", err)
	}
	if got.Status != "success" {
		t.Errorf("run status = %q, want 'success' after /clear", got.Status)
	}
}

// TestSessionLoad_NoCheckpointReturnsAll verifies that when no checkpoint is
// set, SessionLoad returns every non-ephemeral message.
func TestSessionLoad_NoCheckpointReturnsAll(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)

	ctx := context.Background()
	q := dbq.New(testDB.Pool())

	for _, role := range []string{"user", "assistant"} {
		_, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
			ConversationID: toPgUUID(convID),
			Role:           role,
			Content:        role + " hello",
			Source:         "user",
		})
		if err != nil {
			t.Fatalf("CreateMessage: %v", err)
		}
	}

	router := testRouter(ah, func(r chi.Router) {
		r.Get("/api/agent/session/{convID}/messages", ah.SessionLoad)
	})

	req := agentRequest(t, "GET", "/api/agent/session/"+convID.String()+"/messages", agentID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var msgs []session.Message
	if err := json.NewDecoder(rec.Body).Decode(&msgs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("msgs = %d, want 2", len(msgs))
	}
}

// TestSessionLoad_TiedTimestampOrdersBySeq verifies that messages persisted
// in a single transaction (which all share transaction_timestamp() for
// created_at) come back in insertion order. Without the seq tiebreaker on
// agent_messages this returned arbitrary order, orphaning tool_results from
// their assistant tool_use parents and 400'ing strict providers like
// Anthropic.
func TestSessionLoad_TiedTimestampOrdersBySeq(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)

	ctx := context.Background()
	tx, err := testDB.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx)
	q := dbq.New(testDB.Pool()).WithTx(tx)

	// Insert assistant(tool_use) + tool(result) + assistant(text) in one tx
	// so all three rows share an identical created_at.
	rows := []struct {
		role  string
		parts string
	}{
		{"assistant", `[{"type":"tool-call","toolCallId":"toolu_TIE","toolName":"run_js","args":{"code":"1"}}]`},
		{"tool", `[{"type":"tool-result","toolCallId":"toolu_TIE","toolName":"run_js","result":"ok"}]`},
		{"assistant", ""},
	}
	for _, r := range rows {
		params := dbq.CreateMessageParams{
			ConversationID: toPgUUID(convID),
			Role:           r.role,
			Content:        "",
			Source:         "user",
		}
		if r.parts != "" {
			params.Parts = []byte(r.parts)
		} else {
			params.Content = "done"
		}
		if _, err := q.CreateMessage(ctx, params); err != nil {
			t.Fatalf("CreateMessage(%s): %v", r.role, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	q = dbq.New(testDB.Pool())
	loaded, err := q.ListSessionMessagesByConversation(ctx, toPgUUID(convID))
	if err != nil {
		t.Fatalf("ListSessionMessagesByConversation: %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("loaded = %d, want 3", len(loaded))
	}

	// Same created_at across the batch — the tx_timestamp tie we're guarding against.
	if !loaded[0].CreatedAt.Time.Equal(loaded[1].CreatedAt.Time) || !loaded[1].CreatedAt.Time.Equal(loaded[2].CreatedAt.Time) {
		t.Fatalf("expected all three rows to share created_at; got %v / %v / %v",
			loaded[0].CreatedAt.Time, loaded[1].CreatedAt.Time, loaded[2].CreatedAt.Time)
	}

	// Order must follow seq, which mirrors insertion order.
	wantRoles := []string{"assistant", "tool", "assistant"}
	for i, m := range loaded {
		if m.Role != wantRoles[i] {
			t.Errorf("loaded[%d].role = %q, want %q", i, m.Role, wantRoles[i])
		}
	}
	if !(loaded[0].Seq < loaded[1].Seq && loaded[1].Seq < loaded[2].Seq) {
		t.Errorf("seq not strictly increasing: %d, %d, %d",
			loaded[0].Seq, loaded[1].Seq, loaded[2].Seq)
	}
}

// TestExtractCanonicalKeys covers the s3ref parser used by SessionCompact
// cleanup and the newly-wired DeleteConversation cleanup.
func TestExtractCanonicalKeys(t *testing.T) {
	agentID := "11111111-1111-1111-1111-111111111111"
	prefix := "llm/agents/" + agentID + "/"

	tests := []struct {
		name  string
		parts string
		want  []string
	}{
		{
			name:  "empty input returns nil",
			parts: ``,
			want:  nil,
		},
		{
			name:  "malformed json returns nil",
			parts: `not json`,
			want:  nil,
		},
		{
			name:  "text-only parts return nil",
			parts: `[{"type":"text","text":"hello"}]`,
			want:  nil,
		},
		{
			name:  "image with s3ref sentinel",
			parts: `[{"type":"image","image":"s3ref:img-key"}]`,
			want:  []string{prefix + "img-key"},
		},
		{
			name:  "file with s3ref sentinel",
			parts: `[{"type":"file","data":"s3ref:doc-key"}]`,
			want:  []string{prefix + "doc-key"},
		},
		{
			name:  "image without sentinel is ignored",
			parts: `[{"type":"image","image":"https://example.com/foo.png"}]`,
			want:  nil,
		},
		{
			name:  "mixed parts keep order",
			parts: `[{"type":"text","text":"hi"},{"type":"image","image":"s3ref:a"},{"type":"file","data":"s3ref:b"}]`,
			want:  []string{prefix + "a", prefix + "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractCanonicalKeys([]byte(tt.parts), agentID)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got=%v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
