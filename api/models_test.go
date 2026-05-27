package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/airlockrun/agentsdk"
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

	token, err := auth.IssueToken(testJWTSecret, userID, "test@example.com", "user")
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

// TestSync_ModelSlotsReconciliation verifies the sync handler upserts new
// slots, updates declaration fields on re-declare, deletes dropped slots,
// and — critically — preserves the admin-assigned model across resyncs.
func TestSync_ModelSlotsReconciliation(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	ah := testAgentHandler()
	agentID := createTestAgent(t)
	q := dbq.New(testDB.Pool())

	router := testRouter(ah, func(r chi.Router) {
		r.Put("/api/agent/sync", ah.Sync)
	})

	// First sync — declare two slots.
	syncReq := agentsdk.SyncRequest{
		ModelSlots: []agentsdk.ModelSlotDef{
			{Slug: "summarize", Capability: "text", Description: "v1"},
			{Slug: "poster", Capability: "image"},
		},
	}
	req := agentRequest(t, "PUT", "/api/agent/sync", agentID, syncReq)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first sync status = %d; body: %s", rec.Code, rec.Body.String())
	}

	slots, err := q.ListAgentModelSlots(ctx, toPgUUID(agentID))
	if err != nil {
		t.Fatalf("ListAgentModelSlots: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("after first sync slots = %d, want 2", len(slots))
	}

	// Admin assigns a model to one slot.
	if err := q.SetAgentModelSlotAssignment(ctx, dbq.SetAgentModelSlotAssignmentParams{
		AgentID:       toPgUUID(agentID),
		Slug:          "summarize",
		AssignedModel: "openai/gpt-4o",
	}); err != nil {
		t.Fatalf("SetAgentModelSlotAssignment: %v", err)
	}

	// Resync — update summarize's description + drop poster + add thumbnail.
	syncReq = agentsdk.SyncRequest{
		ModelSlots: []agentsdk.ModelSlotDef{
			{Slug: "summarize", Capability: "text", Description: "v2"},
			{Slug: "thumbnail", Capability: "image"},
		},
	}
	req = agentRequest(t, "PUT", "/api/agent/sync", agentID, syncReq)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second sync status = %d; body: %s", rec.Code, rec.Body.String())
	}

	slots, err = q.ListAgentModelSlots(ctx, toPgUUID(agentID))
	if err != nil {
		t.Fatalf("ListAgentModelSlots: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("after resync slots = %d, want 2 (summarize + thumbnail)", len(slots))
	}
	bySlug := map[string]dbq.AgentModelSlot{}
	for _, s := range slots {
		bySlug[s.Slug] = s
	}
	if sum, ok := bySlug["summarize"]; !ok {
		t.Error("summarize missing after resync")
	} else {
		if sum.Description != "v2" {
			t.Errorf("summarize description = %q, want %q", sum.Description, "v2")
		}
		if sum.AssignedModel != "openai/gpt-4o" {
			t.Errorf("summarize assigned_model lost across resync: %q", sum.AssignedModel)
		}
	}
	if _, ok := bySlug["poster"]; ok {
		t.Error("poster should have been deleted as stale")
	}
	if _, ok := bySlug["thumbnail"]; !ok {
		t.Error("thumbnail missing after resync")
	}
}

// TestResolveModel_Precedence covers the four-step resolution chain end-to-end.
func TestResolveModel_Precedence(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	ah := testAgentHandler()
	agentID := createTestAgent(t)
	q := dbq.New(testDB.Pool())

	// Seed a provider row so resolveModel can decrypt the API key for the
	// chosen "provider/model" strings. All assigned model strings below use
	// this same provider ID.
	ciphertext, err := ah.encryptor.Put(ctx, "provider/openai/api_key", "sk-test")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var provUUID uuid.UUID
	if err := testDB.Pool().QueryRow(ctx,
		`INSERT INTO providers (provider_id, slug, display_name, api_key, base_url, is_enabled)
		 VALUES ('openai', 'openai', 'OpenAI', $1, 'https://api.openai.com', true) RETURNING id`,
		ciphertext,
	).Scan(&provUUID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	provFK := toPgUUID(provUUID)

	// Model resolution is provider-FK + bare model name: resolveModel
	// returns the model verbatim and requires a valid provider FK. The
	// singleton system_settings row is migration-seeded; point its exec
	// slot at our provider for the tier-3 default.
	if _, err := testDB.Pool().Exec(ctx,
		`UPDATE system_settings SET default_exec_provider_id=$1, default_exec_model='system-exec' WHERE id=true`,
		provFK,
	); err != nil {
		t.Fatalf("set system default exec model: %v", err)
	}

	resolveTextModel := func(t *testing.T, slug string) string {
		t.Helper()
		_, modelID, _, _, err := ah.resolveModel(ctx, agentID.String(), slug, "text")
		if err != nil {
			t.Fatalf("resolveModel(slug=%q): %v", slug, err)
		}
		return modelID
	}

	t.Run("tier-3 system default", func(t *testing.T) {
		if got := resolveTextModel(t, ""); got != "system-exec" {
			t.Errorf("modelID = %q, want %q", got, "system-exec")
		}
	})

	t.Run("tier-2 per-agent override", func(t *testing.T) {
		if err := q.UpdateAgentModels(ctx, dbq.UpdateAgentModelsParams{
			ID:             toPgUUID(agentID),
			ExecProviderID: provFK,
			ExecModel:      "agent-exec",
		}); err != nil {
			t.Fatalf("UpdateAgentModels: %v", err)
		}
		if got := resolveTextModel(t, ""); got != "agent-exec" {
			t.Errorf("modelID = %q, want %q", got, "agent-exec")
		}
	})

	t.Run("declared-but-unbound slug falls back to tier 2", func(t *testing.T) {
		if err := q.UpsertAgentModelSlot(ctx, dbq.UpsertAgentModelSlotParams{
			AgentID:    toPgUUID(agentID),
			Slug:       "summarize",
			Capability: "text",
		}); err != nil {
			t.Fatalf("UpsertAgentModelSlot: %v", err)
		}
		if got := resolveTextModel(t, "summarize"); got != "agent-exec" {
			t.Errorf("modelID = %q, want %q (tier-2 fallback)", got, "agent-exec")
		}
	})

	t.Run("undeclared slug falls back to tier 2", func(t *testing.T) {
		if got := resolveTextModel(t, "brand-new-slug"); got != "agent-exec" {
			t.Errorf("modelID = %q, want %q (tier-2 fallback)", got, "agent-exec")
		}
	})

	t.Run("tier-1 slot binding wins", func(t *testing.T) {
		if err := q.SetAgentModelSlotAssignment(ctx, dbq.SetAgentModelSlotAssignmentParams{
			AgentID:            toPgUUID(agentID),
			Slug:               "summarize",
			AssignedProviderID: provFK,
			AssignedModel:      "slot-bound",
		}); err != nil {
			t.Fatalf("SetAgentModelSlotAssignment: %v", err)
		}
		if got := resolveTextModel(t, "summarize"); got != "slot-bound" {
			t.Errorf("modelID = %q, want %q", got, "slot-bound")
		}
	})

	t.Run("all-empty capability errors", func(t *testing.T) {
		if _, _, _, _, err := ah.resolveModel(ctx, agentID.String(), "", "image"); err == nil {
			t.Error("expected error when all tiers empty for image capability")
		}
	})
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
	// Untouched columns stayed empty.
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

	// Create a second user who is NOT an admin of the agent.
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
	// Add outsider as a regular 'user' member so requireAccess passes but
	// requireAgentAdmin does not.
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
