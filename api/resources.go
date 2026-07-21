package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	resourcessvc "github.com/airlockrun/airlock/service/resources"
	"github.com/go-chi/chi/v5"
)

// ResourcesHandler serves the per-user available-resource inventory at
// /api/v1/resources. Thin wrapper over service/resources: parse + auth
// principal here; capability resolution and DB access live in the service.
type ResourcesHandler struct {
	svc *resourcessvc.Service
}

func NewResourcesHandler(svc *resourcessvc.Service) *ResourcesHandler {
	if svc == nil {
		panic("api: resources service is required")
	}
	return &ResourcesHandler{svc: svc}
}

// List handles GET /api/v1/resources — the connections / MCP servers / exec
// endpoints available through ownership or grants, with caller capabilities.
func (h *ResourcesHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.svc.List(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to list resources")
		return
	}
	out := make([]*airlockv1.OwnedResourceInfo, len(rows))
	for i, res := range rows {
		out[i] = &airlockv1.OwnedResourceInfo{
			Id:           res.ID.String(),
			Type:         res.Type,
			Slug:         res.Slug,
			Name:         res.Name,
			DisplayName:  res.DisplayName,
			AuthMode:     res.AuthMode,
			Authorized:   res.Authorized,
			AgentCount:   res.AgentCount,
			Capabilities: res.Capabilities,
			CreatedAt:    convert.PgTimestampToProto(res.CreatedAt),
			LastUsedAt:   convert.PgTimestampToProto(res.LastUsedAt),
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListOwnedResourcesResponse{Resources: out})
}

// Rename handles PATCH /api/v1/resources/{type}/{id}.
func (h *ResourcesHandler) Rename(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	req := &airlockv1.RenameResourceRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.Rename(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), id, req.DisplayName); err != nil {
		writeServiceError(w, err, "failed to rename resource")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Consumers handles GET /api/v1/resources/{type}/{id}/consumers.
func (h *ResourcesHandler) Consumers(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	consumers, err := h.svc.Consumers(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), id)
	if err != nil {
		writeServiceError(w, err, "failed to list resource consumers")
		return
	}
	out := make([]*airlockv1.ResourceConsumerInfo, len(consumers))
	for i, consumer := range consumers {
		out[i] = &airlockv1.ResourceConsumerInfo{
			AgentId: consumer.AgentID.String(), AgentName: consumer.AgentName, AgentSlug: consumer.AgentSlug,
			NeedType: consumer.NeedType, NeedSlug: consumer.NeedSlug, CanAccessAgent: consumer.CanAccessAgent,
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListResourceConsumersResponse{Consumers: out})
}

// Revoke handles POST /api/v1/resources/{type}/{id}/revoke — clear an owned
// connection's / MCP server's stored credentials (affects every agent binding it).
func (h *ResourcesHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	if err := h.svc.Revoke(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), id); err != nil {
		writeServiceError(w, err, "failed to revoke credentials")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Delete handles DELETE /api/v1/resources/{type}/{id} — remove an owned resource.
func (h *ResourcesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	if err := h.svc.Delete(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), id); err != nil {
		writeServiceError(w, err, "failed to delete resource")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
