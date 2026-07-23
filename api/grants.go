package api

import (
	"net/http"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	grantssvc "github.com/airlockrun/airlock/service/grants"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// GrantsHandler serves model entitlement management.
type GrantsHandler struct {
	svc *grantssvc.Service
}

func NewGrantsHandler(svc *grantssvc.Service) *GrantsHandler {
	if svc == nil {
		panic("api: grants handler service is required")
	}
	return &GrantsHandler{svc: svc}
}

// GrantModel handles POST /api/v1/model-grants.
func (h *GrantsHandler) GrantModel(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.GrantModelRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	providerID, err := uuid.Parse(req.ProviderId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provider ID")
		return
	}
	granteeID, err := uuid.Parse(req.GranteeId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid grantee ID")
		return
	}
	if err := h.svc.GrantModel(r.Context(), principalFromRequest(r), providerID, req.Model, granteeID); err != nil {
		writeServiceError(w, err, "failed to grant model")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeModelGrant handles DELETE /api/v1/model-grants/{id}.
func (h *GrantsHandler) RevokeModelGrant(w http.ResponseWriter, r *http.Request) {
	grantID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid grant ID")
		return
	}
	if err := h.svc.RevokeModelGrant(r.Context(), principalFromRequest(r), grantID); err != nil {
		writeServiceError(w, err, "failed to revoke model grant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ModelUsage handles GET /api/v1/model-grants/usage?providerId=&model= —
// how a (provider, model) is configured, so the UI can confirm a disable.
func (h *GrantsHandler) ModelUsage(w http.ResponseWriter, r *http.Request) {
	providerID, err := uuid.Parse(r.URL.Query().Get("providerId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid provider ID")
		return
	}
	model := r.URL.Query().Get("model")
	if model == "" {
		writeError(w, http.StatusBadRequest, "model is required")
		return
	}
	count, isDefault, err := h.svc.ModelUsage(r.Context(), principalFromRequest(r), providerID, model)
	if err != nil {
		writeServiceError(w, err, "failed to read model usage")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.ModelUsageResponse{
		AgentCount:      int32(count),
		IsSystemDefault: isDefault,
	})
}

// ListModelGrants handles GET /api/v1/model-grants.
func (h *GrantsHandler) ListModelGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := h.svc.ListModelGrants(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to list model grants")
		return
	}
	out := make([]*airlockv1.ModelGrantInfo, len(grants))
	for i, g := range grants {
		out[i] = &airlockv1.ModelGrantInfo{
			Id:              g.ID.String(),
			ProviderId:      g.ProviderID.String(),
			ProviderCatalog: g.CatalogID,
			ProviderSlug:    g.ProviderSlug,
			Model:           g.Model,
			GranteeId:       g.GranteeID.String(),
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListModelGrantsResponse{Grants: out})
}
