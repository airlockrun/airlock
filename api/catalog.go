package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	catalogsvc "github.com/airlockrun/airlock/service/catalog"
	"go.uber.org/zap"
)

// writeCatalogError maps service sentinels to status codes. 401/403
// come from the authz gate (TenantCatalogView); anything else is the
// per-endpoint fallback.
func writeCatalogError(w http.ResponseWriter, r *http.Request, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, service.ErrUnauthorized):
		writeError(w, status, "not authenticated")
	case errors.Is(err, service.ErrForbidden):
		writeError(w, status, "access denied")
	default:
		logFor(r).Error(fallback, zap.Error(err))
		writeError(w, status, fallback)
	}
}

// catalogHandler owns the read-only catalog surface at /catalog/* —
// providers, models (merged with overlay), and the per-provider
// capability matrix the Settings UI renders. Thin wrapper over
// service/catalog: no per-user gating; the JWT middleware on the route
// group is the access gate.
type catalogHandler struct {
	svc *catalogsvc.Service
}

func newCatalogHandler(svc *catalogsvc.Service) *catalogHandler {
	if svc == nil {
		panic("api: catalog service is required")
	}
	return &catalogHandler{svc: svc}
}

func (h *catalogHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := h.svc.ListProviders(r.Context(), principalFromRequest(r))
	if err != nil {
		writeCatalogError(w, r, err, "failed to load providers")
		return
	}
	out := make([]*airlockv1.ProviderInfo, len(providers))
	for i, p := range providers {
		out[i] = convert.CatalogProviderToProto(p)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListCatalogProvidersResponse{Providers: out})
}

func (h *catalogHandler) ListModels(w http.ResponseWriter, r *http.Request) {
	opts := catalogsvc.ListModelsOptions{
		ProviderFilter: r.URL.Query().Get("provider"),
		ConfiguredOnly: r.URL.Query().Get("configured") == "true",
	}
	models, err := h.svc.ListModels(r.Context(), principalFromRequest(r), opts)
	if err != nil {
		writeCatalogError(w, r, err, "failed to load models")
		return
	}
	out := make([]*airlockv1.ModelInfo, len(models))
	for i, m := range models {
		out[i] = convert.CatalogModelToProto(m)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListCatalogModelsResponse{Models: out})
}

func (h *catalogHandler) ListCapabilities(w http.ResponseWriter, r *http.Request) {
	caps, err := h.svc.ListCapabilities(r.Context(), principalFromRequest(r))
	if err != nil {
		writeCatalogError(w, r, err, "failed to load capabilities")
		return
	}
	out := make([]*airlockv1.ProviderCapabilityInfo, len(caps))
	for i, c := range caps {
		out[i] = convert.ProviderCapabilityToProto(c)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListCapabilitiesResponse{Providers: out})
}
