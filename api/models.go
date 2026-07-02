package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
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

// AllowedModels handles GET /api/v1/models/allowed — the models the caller may
// assign to an agent capability (the picker allow-list).
func (h *modelsHandler) AllowedModels(w http.ResponseWriter, r *http.Request) {
	unrestricted, models, err := h.svc.AllowedModels(r.Context(), principalFromRequest(r))
	if err != nil {
		writeModelsError(w, err, "failed to list allowed models")
		return
	}
	out := make([]*airlockv1.AllowedModel, len(models))
	for i, m := range models {
		out[i] = &airlockv1.AllowedModel{ProviderId: m.ProviderID.String(), Model: m.Model}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListAllowedModelsResponse{Unrestricted: unrestricted, Models: out})
}

// GetConfig handles GET /api/v1/agents/{agentID}/models.
func (h *modelsHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	state, err := h.svc.Get(r.Context(), p, agentID)
	if err != nil {
		writeModelsError(w, err, "failed to load model slots")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.GetAgentModelConfigResponse{
		Config: convert.AgentModelConfigToProto(state.Agent, state.Slots, state.Settings),
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
	p := principalFromRequest(r)
	slots := make([]modelssvc.SlotAssignment, 0, len(cfg.Slots))
	for _, s := range cfg.Slots {
		slots = append(slots, modelssvc.SlotAssignment{
			Slug:       s.Slug,
			ProviderID: s.AssignedProviderId,
			Model:      s.AssignedModel,
		})
	}
	state, err := h.svc.Update(r.Context(), p, agentID, modelssvc.UpdateRequest{
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
		Config: convert.AgentModelConfigToProto(state.Agent, state.Slots, state.Settings),
	})
}
