package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	providerssvc "github.com/airlockrun/airlock/service/providers"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type ProvidersHandler struct {
	svc *providerssvc.Service
}

func NewProvidersHandler(svc *providerssvc.Service) *ProvidersHandler {
	if svc == nil {
		panic("ProvidersHandler: svc is required")
	}
	return &ProvidersHandler{svc: svc}
}

func (h *ProvidersHandler) Create(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.CreateProviderRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	res, err := h.svc.Create(r.Context(), principalFromRequest(r), providerssvc.CreateRequest{
		ProviderID:  req.ProviderId,
		Slug:        req.Slug,
		DisplayName: req.DisplayName,
		APIKey:      req.ApiKey,
		BaseURL:     req.BaseUrl,
	})
	if err != nil {
		writeServiceError(w, err, "failed to create provider")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.CreateProviderResponse{
		Provider: convert.ProviderToProto(res.Row),
	})
}

func (h *ProvidersHandler) List(w http.ResponseWriter, r *http.Request) {
	results, err := h.svc.List(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to list providers")
		return
	}
	out := make([]*airlockv1.Provider, len(results))
	for i, res := range results {
		out[i] = convert.ProviderToProto(res.Row)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListProvidersResponse{Providers: out})
}

func (h *ProvidersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provider ID")
		return
	}
	req := &airlockv1.UpdateProviderRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	res, err := h.svc.Update(r.Context(), principalFromRequest(r), id, providerssvc.UpdateRequest{
		Slug:        req.Slug,
		DisplayName: req.DisplayName,
		BaseURL:     req.BaseUrl,
		APIKey:      req.ApiKey,
		ClearAPIKey: req.ClearApiKey,
		IsEnabled:   req.IsEnabled,
	})
	if err != nil {
		writeServiceError(w, err, "failed to update provider")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.UpdateProviderResponse{
		Provider: convert.ProviderToProto(res.Row),
	})
}

func (h *ProvidersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provider ID")
		return
	}
	if err := h.svc.Delete(r.Context(), principalFromRequest(r), id); err != nil {
		writeServiceError(w, err, "failed to delete provider")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ProvidersHandler) ListModels(w http.ResponseWriter, r *http.Request) {
	id, ok := providerIDParam(w, r)
	if !ok {
		return
	}
	models, err := h.svc.ListModels(r.Context(), principalFromRequest(r), id)
	if err != nil {
		writeServiceError(w, err, "failed to list provider models")
		return
	}
	out := make([]*airlockv1.ProviderModel, len(models))
	for i, model := range models {
		out[i] = convert.ProviderModelToProto(model)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListProviderModelsResponse{Models: out})
}

func (h *ProvidersHandler) ReplaceModels(w http.ResponseWriter, r *http.Request) {
	id, ok := providerIDParam(w, r)
	if !ok {
		return
	}
	req := &airlockv1.ReplaceProviderModelsRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	models := make([]providerssvc.Model, len(req.Models))
	for i, model := range req.Models {
		models[i] = providerssvc.Model{
			ModelID: model.ModelId, DisplayName: model.DisplayName,
			ToolCall: model.ToolCall, Reasoning: model.Reasoning, Vision: model.Vision,
			ContextLimit: model.ContextLimit, OutputLimit: model.OutputLimit,
			StructuredOutputs: model.StructuredOutputs,
			IncludeUsage:      model.IncludeUsage,
		}
	}
	rows, err := h.svc.ReplaceModels(r.Context(), principalFromRequest(r), id, models)
	if err != nil {
		writeServiceError(w, err, "failed to replace provider models")
		return
	}
	out := make([]*airlockv1.ProviderModel, len(rows))
	for i, model := range rows {
		out[i] = convert.ProviderModelToProto(model)
	}
	writeProto(w, http.StatusOK, &airlockv1.ReplaceProviderModelsResponse{Models: out})
}

func (h *ProvidersHandler) DiscoverModels(w http.ResponseWriter, r *http.Request) {
	id, ok := providerIDParam(w, r)
	if !ok {
		return
	}
	candidates, err := h.svc.DiscoverModels(r.Context(), principalFromRequest(r), id)
	if err != nil {
		if errors.Is(err, service.ErrUnauthorized) || errors.Is(err, service.ErrForbidden) ||
			errors.Is(err, service.ErrNotFound) || errors.Is(err, service.ErrInvalidInput) {
			writeServiceError(w, err, "failed to discover provider models")
		} else {
			writeError(w, http.StatusBadGateway, "provider model discovery failed; verify base_url and the configured HTTP network policy")
		}
		return
	}
	out := make([]*airlockv1.ProviderModelCandidate, len(candidates))
	for i, candidate := range candidates {
		out[i] = &airlockv1.ProviderModelCandidate{ModelId: candidate.ModelID}
	}
	writeProto(w, http.StatusOK, &airlockv1.DiscoverProviderModelsResponse{Candidates: out})
}

func providerIDParam(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provider ID")
		return uuid.Nil, false
	}
	return id, true
}
