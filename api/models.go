package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// modelsHandler serves per-agent model configuration endpoints.
type modelsHandler struct {
	db     *db.DB
	logger *zap.Logger

	// agentsHandler owns the access-check helpers; we reuse them here to
	// avoid duplicating the membership resolution logic.
	agents *agentsHandler
}

// GetConfig handles GET /api/v1/agents/{agentID}/models.
// Any agent member can read the current configuration.
func (h *modelsHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.agents.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	slots, err := q.ListAgentModelSlots(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list model slots", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load model slots")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.GetAgentModelConfigResponse{
		Config: agentModelConfigToProto(agent, slots),
	})
}

// UpdateConfig handles PUT /api/v1/agents/{agentID}/models.
// Admin-only. Atomic replace of all eight override columns + each declared
// slot's assigned_model. Only slugs present in the agent's declared slot
// list can be assigned — drift is silently ignored.
func (h *modelsHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	var req airlockv1.UpdateAgentModelConfigRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Config == nil {
		writeError(w, http.StatusBadRequest, "config is required")
		return
	}

	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.agents.requireAgentAdmin(ctx, agent.ID); err != nil {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	cfg := req.Config

	// Each slot is a (provider FK, bare model name) pair. Empty + invalid
	// FK ⇄ inherit system default; both halves must be present together
	// or both must be absent.
	pairs := []struct {
		name      string
		modelName string
		fkRaw     string
	}{
		{"build", cfg.BuildModel, cfg.BuildProviderId},
		{"exec", cfg.ExecModel, cfg.ExecProviderId},
		{"stt", cfg.SttModel, cfg.SttProviderId},
		{"vision", cfg.VisionModel, cfg.VisionProviderId},
		{"tts", cfg.TtsModel, cfg.TtsProviderId},
		{"image_gen", cfg.ImageGenModel, cfg.ImageGenProviderId},
		{"embedding", cfg.EmbeddingModel, cfg.EmbeddingProviderId},
		{"search", cfg.SearchModel, cfg.SearchProviderId},
	}
	parsedFKs := make(map[string]pgtype.UUID, len(pairs))
	for _, p := range pairs {
		fk, err := parseOptionalProviderID(p.fkRaw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid "+p.name+"_provider_id: "+err.Error())
			return
		}
		// Search is provider-scoped, not model-scoped: the runtime picks
		// the search backend by overlay capability on the provider row,
		// not by a stored model name. search_model is always empty by
		// design — only the FK matters. Other slots must move both
		// halves together.
		if p.name != "search" && (p.modelName != "") != fk.Valid {
			writeError(w, http.StatusBadRequest, p.name+"_model and "+p.name+"_provider_id must be set or unset together")
			return
		}
		parsedFKs[p.name] = fk
	}

	if err := q.UpdateAgentModels(ctx, dbq.UpdateAgentModelsParams{
		ID:                  agent.ID,
		BuildProviderID:     parsedFKs["build"],
		BuildModel:          cfg.BuildModel,
		ExecProviderID:      parsedFKs["exec"],
		ExecModel:           cfg.ExecModel,
		SttProviderID:       parsedFKs["stt"],
		SttModel:            cfg.SttModel,
		VisionProviderID:    parsedFKs["vision"],
		VisionModel:         cfg.VisionModel,
		TtsProviderID:       parsedFKs["tts"],
		TtsModel:            cfg.TtsModel,
		ImageGenProviderID:  parsedFKs["image_gen"],
		ImageGenModel:       cfg.ImageGenModel,
		EmbeddingProviderID: parsedFKs["embedding"],
		EmbeddingModel:      cfg.EmbeddingModel,
		SearchProviderID:    parsedFKs["search"],
		SearchModel:         cfg.SearchModel,
	}); err != nil {
		h.logger.Error("update agent models", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to update models")
		return
	}

	// Apply slot assignments. Each slug must already exist as a declared
	// slot (via sync); assignments for unknown slugs are silently dropped.
	existing, err := q.ListAgentModelSlots(ctx, agent.ID)
	if err != nil {
		h.logger.Error("list model slots", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load slots")
		return
	}
	declared := make(map[string]struct{}, len(existing))
	for _, s := range existing {
		declared[s.Slug] = struct{}{}
	}
	for _, s := range cfg.Slots {
		if _, ok := declared[s.Slug]; !ok {
			continue
		}
		fk, err := parseOptionalProviderID(s.AssignedProviderId)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid slot "+s.Slug+" assigned_provider_id: "+err.Error())
			return
		}
		if (s.AssignedModel != "") != fk.Valid {
			writeError(w, http.StatusBadRequest, "slot "+s.Slug+" assigned_model and assigned_provider_id must be set or unset together")
			return
		}
		_ = q.SetAgentModelSlotAssignment(ctx, dbq.SetAgentModelSlotAssignmentParams{
			AgentID:            agent.ID,
			Slug:               s.Slug,
			AssignedProviderID: fk,
			AssignedModel:      s.AssignedModel,
		})
	}

	// Reload to return the authoritative state.
	agent, _ = q.GetAgentByID(ctx, agent.ID)
	slots, _ := q.ListAgentModelSlots(ctx, agent.ID)
	writeProto(w, http.StatusOK, &airlockv1.UpdateAgentModelConfigResponse{
		Config: agentModelConfigToProto(agent, slots),
	})
}

func agentModelConfigToProto(agent dbq.Agent, slots []dbq.AgentModelSlot) *airlockv1.AgentModelConfig {
	out := &airlockv1.AgentModelConfig{
		BuildModel:          agent.BuildModel,
		ExecModel:           agent.ExecModel,
		SttModel:            agent.SttModel,
		VisionModel:         agent.VisionModel,
		TtsModel:            agent.TtsModel,
		ImageGenModel:       agent.ImageGenModel,
		EmbeddingModel:      agent.EmbeddingModel,
		SearchModel:         agent.SearchModel,
		BuildProviderId:     convert.PgUUIDToString(agent.BuildProviderID),
		ExecProviderId:      convert.PgUUIDToString(agent.ExecProviderID),
		SttProviderId:       convert.PgUUIDToString(agent.SttProviderID),
		VisionProviderId:    convert.PgUUIDToString(agent.VisionProviderID),
		TtsProviderId:       convert.PgUUIDToString(agent.TtsProviderID),
		ImageGenProviderId:  convert.PgUUIDToString(agent.ImageGenProviderID),
		EmbeddingProviderId: convert.PgUUIDToString(agent.EmbeddingProviderID),
		SearchProviderId:    convert.PgUUIDToString(agent.SearchProviderID),
	}
	for _, s := range slots {
		out.Slots = append(out.Slots, &airlockv1.ModelSlotInfo{
			Slug:               s.Slug,
			Capability:         s.Capability,
			Description:        s.Description,
			AssignedModel:      s.AssignedModel,
			AssignedProviderId: convert.PgUUIDToString(s.AssignedProviderID),
		})
	}
	return out
}

