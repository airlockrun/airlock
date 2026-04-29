package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

// seedMessages inserts N plain messages into the conversation. Returns the
// seq values in insertion order so tests can use them as cursors.
func seedMessages(t *testing.T, convID pgtype.UUID, n int) []int64 {
	t.Helper()
	ctx := context.Background()
	seqs := make([]int64, n)
	for i := 0; i < n; i++ {
		err := testDB.Pool().QueryRow(ctx,
			`INSERT INTO agent_messages (conversation_id, role, content, tokens_in, tokens_out, cost_estimate, source)
			 VALUES ($1, 'user', $2, 0, 0, 0, 'user') RETURNING seq`,
			convID, "msg "+strconv.Itoa(i)).Scan(&seqs[i])
		if err != nil {
			t.Fatalf("seed message %d: %v", i, err)
		}
	}
	return seqs
}

// TestGetConversation_PaginationFlag verifies the initial-load endpoint:
// with >100 messages seeded, the handler returns the newest 100 in ascending
// order and sets has_older_messages=true. The first message in the response
// should be the 101st-from-last one we seeded.
func TestGetConversation_PaginationFlag(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)

	seeded := seedMessages(t, toPgUUID(convID), 150)

	ch := &conversationsHandler{db: testDB, logger: zap.NewNop()}
	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/conversations/{convID}", ch.GetConversation)
	})

	req := userRequestJSON(t, "GET", "/api/v1/conversations/"+convID.String(), userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.GetConversationResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Messages) != 100 {
		t.Errorf("len(messages) = %d, want 100", len(resp.Messages))
	}
	if !resp.HasOlderMessages {
		t.Error("has_older_messages should be true when >100 messages exist")
	}
	// Newest 100 means the first returned message is the 51st seeded (index 50).
	wantFirstSeq := seeded[50]
	gotFirstSeq := resp.Messages[0].Seq
	if gotFirstSeq != wantFirstSeq {
		t.Errorf("messages[0].seq = %d, want %d (newest 100 window)", gotFirstSeq, wantFirstSeq)
	}
}

// TestListConversationMessages_Backward asserts the `before` cursor returns
// older messages in chronological order, with has_more set when even older
// messages remain.
func TestListConversationMessages_Backward(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)
	seeded := seedMessages(t, toPgUUID(convID), 50)

	ch := &conversationsHandler{db: testDB, logger: zap.NewNop()}
	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/conversations/{convID}/messages", ch.ListConversationMessages)
	})

	// Fetch 20 older than seeded[30]. Expect [10..29] inclusive = 20 msgs.
	before := strconv.FormatInt(seeded[30], 10)
	req := userRequestJSON(t, "GET",
		"/api/v1/conversations/"+convID.String()+"/messages?before="+before+"&limit=20",
		userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rec.Code, rec.Body.String())
	}
	var resp airlockv1.PaginatedMessagesResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Messages) != 20 {
		t.Errorf("len(messages) = %d, want 20", len(resp.Messages))
	}
	if !resp.HasMore {
		t.Error("has_more should be true when messages older than the returned window still exist")
	}
	if resp.Messages[0].Seq != seeded[10] {
		t.Errorf("messages[0].seq = %d, want %d", resp.Messages[0].Seq, seeded[10])
	}
}

// TestListConversationMessages_Forward asserts the `after` cursor returns
// newer messages in chronological order.
func TestListConversationMessages_Forward(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)
	seeded := seedMessages(t, toPgUUID(convID), 20)

	ch := &conversationsHandler{db: testDB, logger: zap.NewNop()}
	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/conversations/{convID}/messages", ch.ListConversationMessages)
	})

	// Fetch messages newer than seeded[5]. Expect [6..19] = 14 msgs, has_more=false.
	after := strconv.FormatInt(seeded[5], 10)
	req := userRequestJSON(t, "GET",
		"/api/v1/conversations/"+convID.String()+"/messages?after="+after+"&limit=100",
		userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rec.Code, rec.Body.String())
	}
	var resp airlockv1.PaginatedMessagesResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Messages) != 14 {
		t.Errorf("len(messages) = %d, want 14", len(resp.Messages))
	}
	if resp.HasMore {
		t.Error("has_more should be false when no more messages exist past the window")
	}
}

// TestListConversationMessages_RequiresDirection rejects requests without
// `before` or `after` to prevent silent full-scans.
func TestListConversationMessages_RequiresDirection(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)

	ch := &conversationsHandler{db: testDB, logger: zap.NewNop()}
	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/conversations/{convID}/messages", ch.ListConversationMessages)
	})

	req := userRequestJSON(t, "GET", "/api/v1/conversations/"+convID.String()+"/messages", userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// TestDeleteConversation_RemovesRow verifies the delete handler removes the
// conversation row even when messages reference attachments (the cleanup
// step must not block the DB delete). S3-side deletion is exercised by the
// ExtractCanonicalKeys unit test; asserting the fire-and-forget delete
// against real S3 would require MinIO and is covered by manual verification.
func TestDeleteConversation_RemovesRow(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()

	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)

	q := dbq.New(testDB.Pool())
	for _, role := range []string{"user", "assistant"} {
		_, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
			ConversationID: toPgUUID(convID),
			Role:           role,
			Content:        role + " message",
			Source:         "user",
		})
		if err != nil {
			t.Fatalf("CreateMessage: %v", err)
		}
	}

	ch := &conversationsHandler{db: testDB, logger: zap.NewNop()}
	router := userRouter(func(r chi.Router) {
		r.Delete("/api/v1/conversations/{convID}", ch.DeleteConversation)
	})

	req := userRequestJSON(t, "DELETE", "/api/v1/conversations/"+convID.String(), userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; body: %s", rec.Code, rec.Body.String())
	}

	if _, err := q.GetConversationByID(ctx, toPgUUID(convID)); err == nil {
		t.Error("expected GetConversationByID to fail after DeleteConversation")
	}
}

// Unused helpers silence go vet on imports that only matter when tests run.
var _ = dbq.ListMessagesBackwardParams{}
