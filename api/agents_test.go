package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

func testAgentsHandler() *agentsHandler {
	return &agentsHandler{
		db:        testDB,
		encryptor: testEncryptor(),
		publicURL: "http://localhost:8080",
		logger:    zap.NewNop(),
	}
}

func TestListAgents(t *testing.T) {
	skipIfNoDB(t)

	agentID, userID := testAgentAndUser(t)
	_ = agentID

	ah := testAgentsHandler()
	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/agents", ah.List)
	})

	req := userRequestJSON(t, "GET", "/api/v1/agents", userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ListAgents: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.ListAgentsResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Agents) == 0 {
		t.Fatal("expected at least 1 agent")
	}
}

func TestGetAgentDetail(t *testing.T) {
	skipIfNoDB(t)

	agentID, userID := testAgentAndUser(t)

	ah := testAgentsHandler()
	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/agents/{agentID}", ah.Get)
	})

	req := userRequestJSON(t, "GET", "/api/v1/agents/"+agentID.String(), userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GetAgent: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.GetAgentDetailResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Agent == nil {
		t.Fatal("expected agent in response")
	}
	if resp.Agent.Id != agentID.String() {
		t.Errorf("agent.id = %q, want %s", resp.Agent.Id, agentID)
	}
}

func TestUpdateAgent(t *testing.T) {
	skipIfNoDB(t)

	agentID, userID := testAgentAndUser(t)

	ah := testAgentsHandler()
	router := userRouter(func(r chi.Router) {
		r.Patch("/api/v1/agents/{agentID}", ah.Update)
	})

	// PATCH only covers non-model fields now; model overrides live on the
	// dedicated /models endpoint (covered by TestUpdateModelConfig_*).
	autoFix := false
	body := map[string]any{"auto_fix": autoFix}
	req := userRequestJSON(t, "PATCH", "/api/v1/agents/"+agentID.String(), userID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("UpdateAgent: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.UpdateAgentResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Agent.AutoFix {
		t.Errorf("auto_fix = true, want false")
	}
}

func TestDeleteAgent(t *testing.T) {
	skipIfNoDB(t)

	agentID, userID := testAgentAndUser(t)

	ah := testAgentsHandler()
	router := userRouter(func(r chi.Router) {
		r.Delete("/api/v1/agents/{agentID}", ah.Delete)
	})

	req := userRequestJSON(t, "DELETE", "/api/v1/agents/"+agentID.String(), userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("DeleteAgent: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify agent is gone.
	q := dbq.New(testDB.Pool())
	_, err := q.GetAgentByID(context.Background(), toPgUUID(agentID))
	if err == nil {
		t.Fatal("expected agent to be deleted")
	}
}

func TestListRuns(t *testing.T) {
	skipIfNoDB(t)

	agentID, userID := testAgentAndUser(t)

	// Insert a test run.
	q := dbq.New(testDB.Pool())
	_, err := q.CreateRun(context.Background(), dbq.CreateRunParams{
		AgentID:      toPgUUID(agentID),
		InputPayload: []byte("{}"),
		TriggerType:  "prompt",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}

	rh := &runsHandler{db: testDB, logger: zap.NewNop()}
	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/agents/{agentID}/runs", rh.ListRuns)
	})

	req := userRequestJSON(t, "GET", "/api/v1/agents/"+agentID.String()+"/runs", userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ListRuns: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.ListRunsResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Runs) == 0 {
		t.Fatal("expected at least 1 run")
	}
}

func TestGetRun(t *testing.T) {
	skipIfNoDB(t)

	agentID, userID := testAgentAndUser(t)

	q := dbq.New(testDB.Pool())
	run, err := q.CreateRun(context.Background(), dbq.CreateRunParams{
		AgentID:      toPgUUID(agentID),
		InputPayload: []byte(`{"test":"data"}`),
		TriggerType:  "prompt",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	runID := pgUUID(run.ID)

	rh := &runsHandler{db: testDB, logger: zap.NewNop()}
	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/runs/{runID}", rh.GetRun)
	})

	req := userRequestJSON(t, "GET", "/api/v1/runs/"+runID.String(), userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GetRun: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.GetRunResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Run.Id != runID.String() {
		t.Errorf("run.id = %q, want %s", resp.Run.Id, runID)
	}
}

func TestConversationCRUD(t *testing.T) {
	skipIfNoDB(t)

	agentID, userID := testAgentAndUser(t)

	ch := &conversationsHandler{db: testDB, logger: zap.NewNop()}
	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/agents/{agentID}/conversations", ch.CreateConversation)
		r.Get("/api/v1/agents/{agentID}/conversations", ch.ListConversations)
		r.Get("/api/v1/conversations/{convID}", ch.GetConversation)
		r.Delete("/api/v1/conversations/{convID}", ch.DeleteConversation)
	})

	// Create
	body := map[string]string{"title": "Test Chat"}
	req := userRequestJSON(t, "POST", "/api/v1/agents/"+agentID.String()+"/conversations", userID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("CreateConversation: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var createResp airlockv1.CreateConversationResponse
	protojson.Unmarshal(rec.Body.Bytes(), &createResp)
	convID := createResp.Conversation.Id

	// List
	req = userRequestJSON(t, "GET", "/api/v1/agents/"+agentID.String()+"/conversations", userID, nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ListConversations: status = %d", rec.Code)
	}
	var listResp airlockv1.ListConversationsResponse
	protojson.Unmarshal(rec.Body.Bytes(), &listResp)
	if len(listResp.Conversations) == 0 {
		t.Fatal("expected at least 1 conversation")
	}

	// Get
	req = userRequestJSON(t, "GET", "/api/v1/conversations/"+convID, userID, nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GetConversation: status = %d", rec.Code)
	}

	// Delete
	req = userRequestJSON(t, "DELETE", "/api/v1/conversations/"+convID, userID, nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("DeleteConversation: status = %d; body: %s", rec.Code, rec.Body.String())
	}
}