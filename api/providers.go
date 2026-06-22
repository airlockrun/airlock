package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
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
