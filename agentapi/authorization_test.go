package agentapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/sol/session"
	"github.com/go-chi/chi/v5"
)

func TestSessionEndpointsRejectOtherAgentConversation(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	ownerAgentID, userID := testAgentAndUser(t)
	otherAgentID, _ := testAgentAndUser(t)
	convID := testConversation(t, ownerAgentID, userID)

	router := testRouter(ah, func(r chi.Router) {
		r.Get("/api/agent/session/{convID}/messages", ah.SessionLoad)
		r.Post("/api/agent/session/{convID}/messages", ah.SessionAppend)
		r.Post("/api/agent/session/{convID}/compact", ah.SessionCompact)
	})

	tests := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{name: "load", method: http.MethodGet, path: "/messages"},
		{name: "append", method: http.MethodPost, path: "/messages", body: []session.Message{{Role: "user", Content: "stolen"}}},
		{name: "compact", method: http.MethodPost, path: "/compact", body: wire.SessionCompactRequest{Summary: []session.Message{{Role: "assistant", Content: "stolen"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := agentRequest(t, tt.method, "/api/agent/session/"+convID.String()+tt.path, otherAgentID, tt.body)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404; body: %s", rec.Code, rec.Body.String())
			}
		})
	}

	msgs, err := dbq.New(testDB.Pool()).ListAllMessagesByConversation(context.Background(), toPgUUID(convID))
	if err != nil {
		t.Fatalf("ListAllMessagesByConversation: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("cross-agent requests inserted %d messages", len(msgs))
	}
}

func TestRunEndpointsRejectOtherAgentRun(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	ownerAgentID, _ := testAgentAndUser(t)
	otherAgentID, otherUserID := testAgentAndUser(t)
	otherConvID := testConversation(t, otherAgentID, otherUserID)
	q := dbq.New(testDB.Pool())
	run, err := q.CreateRun(context.Background(), dbq.CreateRunParams{
		AgentID: toPgUUID(ownerAgentID), InputPayload: []byte("{}"), SourceRef: "", TriggerType: "code", TriggerRef: "",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := q.UpdateRunCheckpoint(context.Background(), dbq.UpdateRunCheckpointParams{
		ID: run.ID, Checkpoint: []byte(`{"owner":true}`),
	}); err != nil {
		t.Fatalf("UpdateRunCheckpoint: %v", err)
	}

	router := testRouter(ah, func(r chi.Router) {
		r.Post("/api/agent/run/complete", ah.RunComplete)
		r.Get("/api/agent/run/{runID}/checkpoint", ah.GetCheckpoint)
		r.Post("/api/agent/session/{convID}/messages", ah.SessionAppend)
		r.Post("/api/agent/llm/stream", ah.LLMStream)
	})

	req := agentRequest(t, http.MethodPost, "/api/agent/run/complete", otherAgentID, wire.RunCompleteRequest{
		RunID: pgUUID(run.ID).String(), Status: "success",
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("complete status = %d, want 404; body: %s", rec.Code, rec.Body.String())
	}

	got, err := q.GetRunByID(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("GetRunByID: %v", err)
	}
	if got.Status != "running" {
		t.Errorf("run status = %q, want running", got.Status)
	}

	req = agentRequest(t, http.MethodGet, "/api/agent/run/"+pgUUID(run.ID).String()+"/checkpoint", otherAgentID, nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("checkpoint status = %d, want 404; body: %s", rec.Code, rec.Body.String())
	}

	req = agentRequest(t, http.MethodPost, "/api/agent/session/"+otherConvID.String()+"/messages?runId="+pgUUID(run.ID).String(), otherAgentID, []session.Message{{Role: "user", Content: "stolen run"}})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("append status = %d, want 404; body: %s", rec.Code, rec.Body.String())
	}

	req = agentRequest(t, http.MethodPost, "/api/agent/llm/stream", otherAgentID, map[string]any{})
	req.Header.Set("X-Airlock-Run-ID", pgUUID(run.ID).String())
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("llm status = %d, want 404; body: %s", rec.Code, rec.Body.String())
	}
}

func TestPrintTopicsAndUpgradeRejectOtherAgentConversation(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	ownerAgentID, userID := testAgentAndUser(t)
	otherAgentID, _ := testAgentAndUser(t)
	convID := testConversation(t, ownerAgentID, userID)
	q := dbq.New(testDB.Pool())
	if err := q.UpsertTopic(context.Background(), dbq.UpsertTopicParams{
		AgentID: toPgUUID(otherAgentID), Slug: "updates", Description: "", LlmHint: "", Access: "user",
	}); err != nil {
		t.Fatalf("UpsertTopic: %v", err)
	}

	router := testRouter(ah, func(r chi.Router) {
		r.Post("/api/agent/print", ah.Print)
		r.Post("/api/agent/topic/{slug}/subscribe", ah.TopicSubscribe)
		r.Delete("/api/agent/topic/{slug}/subscribe", ah.TopicUnsubscribe)
		r.Post("/api/agent/upgrade", ah.Upgrade)
	})

	tests := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{name: "print", method: http.MethodPost, path: "/api/agent/print", body: wire.PrintRequest{
			ConversationID: convID.String(), Parts: []wire.DisplayPart{{Type: "text", Text: "stolen"}},
		}},
		{name: "subscribe", method: http.MethodPost, path: "/api/agent/topic/updates/subscribe", body: map[string]string{"conversationId": convID.String()}},
		{name: "unsubscribe", method: http.MethodDelete, path: "/api/agent/topic/updates/subscribe", body: map[string]string{"conversationId": convID.String()}},
		{name: "upgrade", method: http.MethodPost, path: "/api/agent/upgrade", body: map[string]string{"conversationId": convID.String(), "description": "stolen"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := agentRequest(t, tt.method, tt.path, otherAgentID, tt.body)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404; body: %s", rec.Code, rec.Body.String())
			}
		})
	}

	msgs, err := q.ListAllMessagesByConversation(context.Background(), toPgUUID(convID))
	if err != nil {
		t.Fatalf("ListAllMessagesByConversation: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("cross-agent operations inserted %d messages", len(msgs))
	}
}
