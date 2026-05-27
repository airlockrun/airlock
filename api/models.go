package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	modelssvc "github.com/airlockrun/airlock/service/models"
	"github.com/go-chi/chi/v5"
)

// modelsHandler is the thin HTTP wrapper over models.Service.
type modelsHandler struct {
	svc *modelssvc.Service
}

func newModelsHandler(svc *modelssvc.Service) *modelsHandler {
	if svc == nil {
		panic("api: models.Service is required")
	}
	return &modelsHandler{svc: svc}
}

func writeModelsError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	var msg string
	switch {
	case errors.Is(err, service.ErrInvalidInput):
		// Detail-wrapped: surface the specific reason.
		msg = err.Error()
	case errors.Is(err, service.ErrUnauthorized):
		msg = "unauthorized"
	case errors.Is(err, service.ErrForbidden):
		msg = "access denied"
	case errors.Is(err, service.ErrNotFound):
		msg = "agent not found"
	default:
		msg = fallback
	}
	writeError(w, status, msg)
}

// GetConfig handles GET /api/v1/agents/{agentID}/models.
func (h *modelsHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	state, err := h.svc.Get(r.Context(), userID, agentID)
	if err != nil {
		writeModelsError(w, err, "failed to load model slots")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.GetAgentModelConfigResponse{
		Config: agentModelConfigToProto(state.Agent, state.Slots),
	})
}

// UpdateConfig handles PUT /api/v1/agents/{agentID}/models.
func (h *modelsHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
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
	cfg := req.Config
	userID := auth.UserIDFromContext(r.Context())
	slots := make([]modelssvc.SlotAssignment, 0, len(cfg.Slots))
	for _, s := range cfg.Slots {
		slots = append(slots, modelssvc.SlotAssignment{
			Slug:       s.Slug,
			ProviderID: s.AssignedProviderId,
			Model:      s.AssignedModel,
		})
	}
	state, err := h.svc.Update(r.Context(), userID, agentID, modelssvc.UpdateRequest{
		Build:     modelssvc.Pair{ProviderID: cfg.BuildProviderId, Model: cfg.BuildModel},
		Exec:      modelssvc.Pair{ProviderID: cfg.ExecProviderId, Model: cfg.ExecModel},
		STT:       modelssvc.Pair{ProviderID: cfg.SttProviderId, Model: cfg.SttModel},
		Vision:    modelssvc.Pair{ProviderID: cfg.VisionProviderId, Model: cfg.VisionModel},
		TTS:       modelssvc.Pair{ProviderID: cfg.TtsProviderId, Model: cfg.TtsModel},
		ImageGen:  modelssvc.Pair{ProviderID: cfg.ImageGenProviderId, Model: cfg.ImageGenModel},
		Embedding: modelssvc.Pair{ProviderID: cfg.EmbeddingProviderId, Model: cfg.EmbeddingModel},
		Search:    modelssvc.Pair{ProviderID: cfg.SearchProviderId, Model: cfg.SearchModel},
		Slots:     slots,
	})
	if err != nil {
		writeModelsError(w, err, "failed to update models")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.UpdateAgentModelConfigResponse{
		Config: agentModelConfigToProto(state.Agent, state.Slots),
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
