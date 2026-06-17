package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	resourcessvc "github.com/airlockrun/airlock/service/resources"
	"github.com/go-chi/chi/v5"
)

// ResourcesHandler serves the per-user owned-resource inventory at
// /api/v1/resources. Thin wrapper over service/resources: parse + auth
// principal here; the owner-scoping and DB live in the service.
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
// endpoints the caller owns, with each one's agent-bind count.
func (h *ResourcesHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.svc.List(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to list resources")
		return
	}
	out := make([]*airlockv1.OwnedResourceInfo, len(rows))
	for i, res := range rows {
		out[i] = &airlockv1.OwnedResourceInfo{
			Id:         res.ID.String(),
			Type:       res.Type,
			Slug:       res.Slug,
			Name:       res.Name,
			AuthMode:   res.AuthMode,
			Authorized: res.Authorized,
			AgentCount: res.AgentCount,
			CreatedAt:  convert.PgTimestampToProto(res.CreatedAt),
			LastUsedAt: convert.PgTimestampToProto(res.LastUsedAt),
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListOwnedResourcesResponse{Resources: out})
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
