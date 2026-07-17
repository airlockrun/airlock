package agentapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

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
	syncReq := wire.SyncRequest{
		ModelSlots: []wire.ModelSlotDef{
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
	syncReq = wire.SyncRequest{
		ModelSlots: []wire.ModelSlotDef{
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

	provUUID := uuid.New()
	ciphertext, err := ah.encryptor.Put(ctx, "provider/"+provUUID.String()+"/api_key", "sk-test")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := testDB.Pool().QueryRow(ctx,
		`INSERT INTO providers (id, provider_id, slug, display_name, api_key, base_url, is_enabled)
		 VALUES ($1, 'openai', 'openai', 'OpenAI', $2, 'https://api.openai.com', true) RETURNING id`,
		provUUID, ciphertext,
	).Scan(&provUUID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	provFK := toPgUUID(provUUID)

	if _, err := testDB.Pool().Exec(ctx,
		`UPDATE system_settings SET default_exec_provider_id=$1, default_exec_model='system-exec' WHERE id=true`,
		provFK,
	); err != nil {
		t.Fatalf("set system default exec model: %v", err)
	}

	resolveTextModel := func(t *testing.T, slug string) string {
		t.Helper()
		_, _, modelID, _, _, err := ah.resolveModel(ctx, agentID.String(), slug, "text")
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

	t.Run("undeclared slug is a loud error", func(t *testing.T) {
		if _, _, _, _, _, err := ah.resolveModel(ctx, agentID.String(), "brand-new-slug", "text"); err == nil {
			t.Error("expected error for an unregistered slug, got nil")
		}
	})

	t.Run("unbound slot uses slot capability, not request capability", func(t *testing.T) {
		// A vision slot left unbound must fall back to the VISION default even
		// when the request carries capability="text" — the slot owns the
		// capability. Regression for vision calls silently routing to the
		// text/exec model.
		if _, err := testDB.Pool().Exec(ctx,
			`UPDATE system_settings SET default_vision_provider_id=$1, default_vision_model='system-vision' WHERE id=true`,
			provFK,
		); err != nil {
			t.Fatalf("set system default vision model: %v", err)
		}
		if err := q.UpsertAgentModelSlot(ctx, dbq.UpsertAgentModelSlotParams{
			AgentID:    toPgUUID(agentID),
			Slug:       "see-food",
			Capability: "vision",
		}); err != nil {
			t.Fatalf("UpsertAgentModelSlot: %v", err)
		}
		_, _, modelID, _, _, err := ah.resolveModel(ctx, agentID.String(), "see-food", "text")
		if err != nil {
			t.Fatalf("resolveModel(slug=see-food): %v", err)
		}
		if modelID != "system-vision" {
			t.Errorf("modelID = %q, want %q (slot capability governs)", modelID, "system-vision")
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
		if _, _, _, _, _, err := ah.resolveModel(ctx, agentID.String(), "", "image"); err == nil {
			t.Error("expected error when all tiers empty for image capability")
		}
	})
}
