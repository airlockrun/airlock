package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	resourcessvc "github.com/airlockrun/airlock/service/resources"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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

// List handles GET /api/v1/resources. It returns reusable resources available
// through ownership or grants, with caller capabilities.
func (h *ResourcesHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.svc.List(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to list resources")
		return
	}
	out := make([]*airlockv1.OwnedResourceInfo, len(rows))
	for i, res := range rows {
		info := &airlockv1.OwnedResourceInfo{
			Id:           res.ID.String(),
			Type:         res.Type,
			Slug:         res.Slug,
			Name:         res.Name,
			DisplayName:  res.DisplayName,
			AuthMode:     res.AuthMode,
			Authorized:   res.Authorized,
			AgentCount:   res.AgentCount,
			Capabilities: res.Capabilities,
			OwnerUserId:  res.OwnerID.String(),
			OwnerName:    res.OwnerName,
			CreatedAt:    convert.PgTimestampToProto(res.CreatedAt),
		}
		if res.HostID != uuid.Nil {
			info.HostId = res.HostID.String()
		}
		if res.Connector != nil {
			info.ConnectorStatus = &airlockv1.ConnectorResourceStatusInfo{
				Readiness: res.Connector.Readiness, ReadinessDetail: res.Connector.ReadinessDetail,
				Online: res.Connector.Online, Lifecycle: res.Connector.Lifecycle,
				ProtocolMajor: res.Connector.ProtocolMajor, ProtocolMinor: res.Connector.ProtocolMinor,
				ArtifactVersion: res.Connector.ArtifactVersion, ArtifactDigest: res.Connector.ArtifactDigest,
				InterfaceHash: res.Connector.InterfaceHash, ArtifactFreshness: res.Connector.ArtifactFreshness,
				UpdateStatus: res.Connector.UpdateStatus, LatestArtifactVersion: res.Connector.LatestArtifactVersion,
				LastHeartbeatAt:  convert.PgTimestampToProto(res.Connector.LastHeartbeatAt),
				ActiveProvenance: res.Connector.ActiveProvenance, ActiveObservationState: res.Connector.ActiveObservationState,
				ObservedActiveDigest: res.Connector.ObservedActiveDigest, InventoryRevision: res.Connector.InventoryRevision,
			}
		}
		out[i] = info
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
		if consumer.CanAccessAgent {
			out[i].AgentDetailPath = "/agents/" + consumer.AgentSlug
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListResourceConsumersResponse{Consumers: out})
}

func (h *ResourcesHandler) ListGrants(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	grants, err := h.svc.ListGrants(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), id)
	if err != nil {
		writeServiceError(w, err, "failed to list resource grants")
		return
	}
	out := make([]*airlockv1.ResourceGrantInfo, len(grants))
	for i, grant := range grants {
		out[i] = &airlockv1.ResourceGrantInfo{
			Id: grant.ID.String(), UserId: grant.UserID.String(), Email: grant.Email,
			DisplayName: grant.DisplayName, Capabilities: grant.Capabilities,
			CreatedAt: convert.PgTimestampToProto(grant.CreatedAt),
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListResourceGrantsResponse{Grants: out})
}

func (h *ResourcesHandler) UpsertGrant(w http.ResponseWriter, r *http.Request) {
	id, userID, ok := resourceAndUserIDs(w, r)
	if !ok {
		return
	}
	req := &airlockv1.UpsertResourceGrantRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.UpsertGrant(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), id, userID, req.Capabilities); err != nil {
		writeServiceError(w, err, "failed to update resource grant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ResourcesHandler) DeleteGrant(w http.ResponseWriter, r *http.Request) {
	id, userID, ok := resourceAndUserIDs(w, r)
	if !ok {
		return
	}
	if err := h.svc.DeleteGrant(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), id, userID); err != nil {
		writeServiceError(w, err, "failed to delete resource grant")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ResourcesHandler) Transfer(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	req := &airlockv1.TransferResourceOwnershipRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	newOwnerID, err := uuid.Parse(req.NewOwnerUserId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid new owner user ID")
		return
	}
	if err := h.svc.Transfer(r.Context(), principalFromRequest(r), chi.URLParam(r, "type"), id, newOwnerID); err != nil {
		writeServiceError(w, err, "failed to transfer resource ownership")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func resourceAndUserIDs(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	id, resourceErr := parseUUID(chi.URLParam(r, "id"))
	userID, userErr := parseUUID(chi.URLParam(r, "userID"))
	if resourceErr != nil || userErr != nil {
		writeError(w, http.StatusBadRequest, "invalid resource or user ID")
		return uuid.Nil, uuid.Nil, false
	}
	return id, userID, true
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
