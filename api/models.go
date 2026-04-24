package api

import (
	"net/http"
	"strings"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
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

	// Validate any non-empty model string matches the "provider/model" format.
	for _, pair := range [][2]string{
		{"build_model", cfg.BuildModel},
		{"exec_model", cfg.ExecModel},
		{"stt_model", cfg.SttModel},
		{"vision_model", cfg.VisionModel},
		{"tts_model", cfg.TtsModel},
		{"image_gen_model", cfg.ImageGenModel},
		{"embedding_model", cfg.EmbeddingModel},
		{"search_model", cfg.SearchModel},
	} {
		if pair[1] != "" && !strings.Contains(pair[1], "/") {
			writeError(w, http.StatusBadRequest, pair[0]+" must be in provider/model format")
			return
		}
	}
	for _, s := range cfg.Slots {
		if s.AssignedModel != "" && !strings.Contains(s.AssignedModel, "/") {
			writeError(w, http.StatusBadRequest, "slot "+s.Slug+" assigned_model must be in provider/model format")
			return
		}
	}

	if err := q.UpdateAgentModels(ctx, dbq.UpdateAgentModelsParams{
		ID:             agent.ID,
		BuildModel:     cfg.BuildModel,
		ExecModel:      cfg.ExecModel,
		SttModel:       cfg.SttModel,
		VisionModel:    cfg.VisionModel,
		TtsModel:       cfg.TtsModel,
		ImageGenModel:  cfg.ImageGenModel,
		EmbeddingModel: cfg.EmbeddingModel,
		SearchModel:    cfg.SearchModel,
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
		_ = q.SetAgentModelSlotAssignment(ctx, dbq.SetAgentModelSlotAssignmentParams{
			AgentID:       agent.ID,
			Slug:          s.Slug,
			AssignedModel: s.AssignedModel,
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
		BuildModel:     agent.BuildModel,
		ExecModel:      agent.ExecModel,
		SttModel:       agent.SttModel,
		VisionModel:    agent.VisionModel,
		TtsModel:       agent.TtsModel,
		ImageGenModel:  agent.ImageGenModel,
		EmbeddingModel: agent.EmbeddingModel,
		SearchModel:    agent.SearchModel,
	}
	for _, s := range slots {
		out.Slots = append(out.Slots, &airlockv1.ModelSlotInfo{
			Slug:          s.Slug,
			Capability:    s.Capability,
			Description:   s.Description,
			AssignedModel: s.AssignedModel,
		})
	}
	return out
}

