package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	modelssvc "github.com/airlockrun/airlock/service/models"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// userRequestProto creates a PUT/POST request with a protojson body and a
// user JWT. Used for proto-typed endpoints.
func userRequestProto(t *testing.T, method, path string, userID uuid.UUID, msg proto.Message) *http.Request {
	t.Helper()
	var body []byte
	if msg != nil {
		b, err := protojson.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal proto: %v", err)
		}
		body = b
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	token, err := auth.IssueToken(testJWTSecret, userID, "test@example.com", "user", false)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// testModelsHandler wires a modelsHandler against the shared test DB.
func testModelsHandler() *modelsHandler {
	return newModelsHandler(modelssvc.New(testDB, zap.NewNop()))
}

// TestUpdateModelConfig_AtomicReplaceAndSlotAssignment verifies PUT
// /api/v1/agents/{id}/models writes all eight columns plus slot assignments
// in one shot, preserving slot declarations untouched.
func TestUpdateModelConfig_AtomicReplaceAndSlotAssignment(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	mH := testModelsHandler()
	agentID, userID := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())

	// Model config is provider-FK + bare model name; each *_model must be
	// accompanied by a valid *_provider_id. Seed a provider to point at.
	var provUUID uuid.UUID
	if err := testDB.Pool().QueryRow(ctx,
		`INSERT INTO providers (provider_id, slug, display_name, api_key, base_url, is_enabled)
		 VALUES ('openai', 'openai', 'OpenAI', '', '', true) RETURNING id`,
	).Scan(&provUUID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	prov := provUUID.String()

	// Declare a slot so the PUT has a known slug to bind.
	if err := q.UpsertAgentModelSlot(ctx, dbq.UpsertAgentModelSlotParams{
		AgentID:    toPgUUID(agentID),
		Slug:       "summarize",
		Capability: "text",
	}); err != nil {
		t.Fatalf("UpsertAgentModelSlot: %v", err)
	}

	router := userRouter(func(r chi.Router) {
		r.Put("/api/v1/agents/{agentID}/models", mH.UpdateConfig)
		r.Get("/api/v1/agents/{agentID}/models", mH.GetConfig)
	})

	body := &airlockv1.UpdateAgentModelConfigRequest{
		Config: &airlockv1.AgentModelConfig{
			ExecModel:        "gpt-4o",
			ExecProviderId:   prov,
			VisionModel:      "claude-vision",
			VisionProviderId: prov,
			Slots: []*airlockv1.ModelSlotInfo{
				{Slug: "summarize", AssignedModel: "gpt-4o-mini", AssignedProviderId: prov},
				{Slug: "never-declared", AssignedModel: "ghost", AssignedProviderId: prov}, // silently ignored
			},
		},
	}
	req := userRequestProto(t, "PUT", "/api/v1/agents/"+agentID.String()+"/models", userID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d; body: %s", rec.Code, rec.Body.String())
	}

	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	if agent.ExecModel != "gpt-4o" || agent.VisionModel != "claude-vision" {
		t.Errorf("agent columns not updated: exec=%q vision=%q", agent.ExecModel, agent.VisionModel)
	}
	if agent.ExecProviderID != toPgUUID(provUUID) || agent.VisionProviderID != toPgUUID(provUUID) {
		t.Errorf("provider FKs not set: exec=%v vision=%v", agent.ExecProviderID, agent.VisionProviderID)
	}
	if agent.BuildModel != "" || agent.SttModel != "" {
		t.Errorf("unset columns clobbered: build=%q stt=%q", agent.BuildModel, agent.SttModel)
	}

	slot, err := q.GetAgentModelSlot(ctx, dbq.GetAgentModelSlotParams{
		AgentID: toPgUUID(agentID),
		Slug:    "summarize",
	})
	if err != nil {
		t.Fatalf("GetAgentModelSlot: %v", err)
	}
	if slot.AssignedModel != "gpt-4o-mini" {
		t.Errorf("summarize.assigned_model = %q, want %q", slot.AssignedModel, "gpt-4o-mini")
	}

	// never-declared assignment was ignored — no new row inserted.
	all, err := q.ListAgentModelSlots(ctx, toPgUUID(agentID))
	if err != nil {
		t.Fatalf("ListAgentModelSlots: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("slots count = %d, want 1 (only summarize)", len(all))
	}
}

// TestUpdateModelConfig_AdminOnly verifies a non-admin member cannot PUT.
func TestUpdateModelConfig_AdminOnly(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	mH := testModelsHandler()
	agentID, _ := testAgentAndUser(t)

	q := dbq.New(testDB.Pool())
	suffix := uuid.New().String()[:8]
	outsider, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "outsider-" + suffix + "@example.com",
		DisplayName: "Outsider",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := q.AddAgentMember(ctx, dbq.AddAgentMemberParams{
		AgentID: toPgUUID(agentID),
		UserID:  outsider.ID,
		Role:    "user",
	}); err != nil {
		t.Fatalf("AddAgentMember: %v", err)
	}

	router := userRouter(func(r chi.Router) {
		r.Put("/api/v1/agents/{agentID}/models", mH.UpdateConfig)
	})

	body := &airlockv1.UpdateAgentModelConfigRequest{
		Config: &airlockv1.AgentModelConfig{ExecModel: "openai/gpt-4o"},
	}
	req := userRequestProto(t, "PUT", "/api/v1/agents/"+agentID.String()+"/models", pgUUID(outsider.ID), body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}
