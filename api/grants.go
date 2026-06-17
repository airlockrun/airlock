package api

import (
	"net/http"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	grantssvc "github.com/airlockrun/airlock/service/grants"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// GrantsHandler serves resource-grant and model-grant management. Resource
// grants are authorized by the manage capability on the resource (in the
// service); model grants are tenant-admin only.
type GrantsHandler struct {
	svc *grantssvc.Service
}

func NewGrantsHandler(svc *grantssvc.Service) *GrantsHandler {
	if svc == nil {
		panic("api: grants handler service is required")
	}
	return &GrantsHandler{svc: svc}
}

// GrantResource handles POST /api/v1/resources/{type}/{id}/grants.
func (h *GrantsHandler) GrantResource(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	req := &airlockv1.GrantResourceRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	granteeID, err := uuid.Parse(req.GranteeId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid grantee ID")
		return
	}
	if err := h.svc.GrantResource(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), resourceID, granteeID, req.Capabilities); err != nil {
		writeServiceError(w, err, "failed to grant resource")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RevokeResourceGrant handles DELETE /api/v1/resources/{type}/{id}/grants/{grantID}.
func (h *GrantsHandler) RevokeResourceGrant(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	grantID, err := uuid.Parse(chi.URLParam(r, "grantID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid grant ID")
		return
	}
	if err := h.svc.RevokeResourceGrant(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), resourceID, grantID); err != nil {
		writeServiceError(w, err, "failed to revoke grant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListResourceGrants handles GET /api/v1/resources/{type}/{id}/grants.
func (h *GrantsHandler) ListResourceGrants(w http.ResponseWriter, r *http.Request) {
	resourceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	grants, err := h.svc.ListResourceGrants(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), resourceID)
	if err != nil {
		writeServiceError(w, err, "failed to list grants")
		return
	}
	out := make([]*airlockv1.ResourceGrantInfo, len(grants))
	for i, g := range grants {
		out[i] = &airlockv1.ResourceGrantInfo{GranteeId: g.GranteeID.String(), Capabilities: g.Capabilities}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListResourceGrantsResponse{Grants: out})
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
