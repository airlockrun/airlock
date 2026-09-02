package api

import (
	"net/http"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	needssvc "github.com/airlockrun/airlock/service/needs"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// NeedsHandler serves the agent resource-need surface: list needs, list
// shape-compatible candidate resources for a need, bind an existing resource,
// or create a new one from the need's spec.
type NeedsHandler struct {
	svc *needssvc.Service
}

func NewNeedsHandler(svc *needssvc.Service) *NeedsHandler {
	if svc == nil {
		panic("api: needs handler service is required")
	}
	return &NeedsHandler{svc: svc}
}

// ListNeeds handles GET /api/v1/agents/{agentID}/needs.
func (h *NeedsHandler) ListNeeds(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	needs, err := h.svc.ListNeeds(r.Context(), principalFromRequest(r), agentID)
	if err != nil {
		writeServiceError(w, err, "failed to list needs")
		return
	}
	out := make([]*airlockv1.NeedInfo, len(needs))
	for i, n := range needs {
		out[i] = needToProto(n)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListNeedsResponse{Needs: out})
}

func needToProto(need needssvc.NeedInfo) *airlockv1.NeedInfo {
	info := &airlockv1.NeedInfo{
		Type: need.Type, Slug: need.Slug, Description: need.Description, Bound: need.Bound,
		ConnectorContractId: need.ConnectorContractID, ConnectorMultiple: need.ConnectorMultiple,
		BoundConnectorGroupName: need.BoundConnectorGroupName,
	}
	if need.Bound {
		info.BoundResourceId = need.BoundResourceID.String()
	}
	if need.BoundConnectorID != uuid.Nil {
		info.BoundConnectorId = need.BoundConnectorID.String()
	}
	if need.BoundConnectorGroupID != uuid.Nil {
		info.BoundConnectorGroupId = need.BoundConnectorGroupID.String()
	}
	info.ConnectorRequiredCommands = make([]*airlockv1.ConnectorNeedCommandInfo, len(need.ConnectorCommands))
	for i, command := range need.ConnectorCommands {
		info.ConnectorRequiredCommands[i] = &airlockv1.ConnectorNeedCommandInfo{
			Name: command.Name, Revision: command.Revision, Mode: command.Mode,
			InputSchemaHash: command.InputSchemaHash, OutputSchemaHash: command.OutputSchemaHash,
			Description: command.Description, InputSchemaJson: string(command.InputSchema), OutputSchemaJson: string(command.OutputSchema),
		}
	}
	info.ConnectorRequiredDirectories = make([]*airlockv1.ConnectorNeedDirectoryInfo, len(need.ConnectorDirectories))
	for i, directory := range need.ConnectorDirectories {
		info.ConnectorRequiredDirectories[i] = &airlockv1.ConnectorNeedDirectoryInfo{
			Name: directory.Name, Revision: directory.Revision,
			Read: directory.Read, Write: directory.Write, List: directory.List,
		}
	}
	return info
}

// ListCandidates handles GET /api/v1/agents/{agentID}/needs/{type}/{slug}/candidates.
func (h *NeedsHandler) ListCandidates(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	cands, err := h.svc.ListCandidates(r.Context(), principalFromRequest(r), agentID, chi.URLParam(r, "type"), chi.URLParam(r, "slug"))
	if err != nil {
		writeServiceError(w, err, "failed to list candidates")
		return
	}
	out := make([]*airlockv1.CandidateInfo, len(cands))
	for i, c := range cands {
		out[i] = &airlockv1.CandidateInfo{
			ResourceId: c.ResourceID.String(), Name: c.Name, DisplayName: c.DisplayName, Slug: c.Slug,
			Readiness: c.Readiness, Authorized: c.Authorized, Configured: c.Configured,
			AgentCount: c.AgentCount, RequiredScopes: c.Required, MissingScopes: c.Missing, Capabilities: c.Capabilities,
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListCandidatesResponse{Candidates: out})
}

func (h *NeedsHandler) ListConnectorTargetGroupCandidates(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	candidates, err := h.svc.ListConnectorTargetGroupCandidates(r.Context(), principalFromRequest(r), agentID, chi.URLParam(r, "slug"))
	if err != nil {
		writeServiceError(w, err, "failed to list connector target groups")
		return
	}
	out := make([]*airlockv1.ConnectorTargetGroupCandidateInfo, len(candidates))
	for i, candidate := range candidates {
		out[i] = &airlockv1.ConnectorTargetGroupCandidateInfo{
			Group:    connectorTargetGroupToProto(candidate.Group, candidate.MemberCount, candidate.ReadyMemberCount),
			Eligible: candidate.Eligible, CompatibleReadyMemberCount: candidate.CompatibleReadyMemberCount,
			Reason: candidate.Reason,
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListConnectorTargetGroupCandidatesResponse{Candidates: out})
}

// UnbindNeed handles DELETE /api/v1/agents/{agentID}/needs/{type}/{slug}/bind.
func (h *NeedsHandler) UnbindNeed(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	if err := h.svc.Unbind(r.Context(), principalFromRequest(r), agentID, chi.URLParam(r, "type"), chi.URLParam(r, "slug")); err != nil {
		writeServiceError(w, err, "failed to unbind resource")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// BindNeed handles POST /api/v1/agents/{agentID}/needs/{type}/{slug}/bind.
func (h *NeedsHandler) BindNeed(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	req := &airlockv1.BindNeedRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resourceID, err := uuid.Parse(req.ResourceId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resource ID")
		return
	}
	if err := h.svc.BindExisting(r.Context(), principalFromRequest(r), agentID, chi.URLParam(r, "type"), chi.URLParam(r, "slug"), resourceID); err != nil {
		writeServiceError(w, err, "failed to bind resource")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *NeedsHandler) BindConnectorGroup(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	request := &airlockv1.BindConnectorGroupRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	groupID, err := uuid.Parse(request.TargetGroupId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target group ID")
		return
	}
	if err := h.svc.BindConnectorGroup(r.Context(), principalFromRequest(r), agentID, chi.URLParam(r, "slug"), groupID); err != nil {
		writeServiceError(w, err, "failed to bind connector target group")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CreateForNeed handles POST /api/v1/agents/{agentID}/needs/{type}/{slug}/create.
func (h *NeedsHandler) CreateForNeed(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	req := &airlockv1.CreateForNeedRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id, err := h.svc.CreateResourceForNeed(r.Context(), principalFromRequest(r), agentID, chi.URLParam(r, "type"), chi.URLParam(r, "slug"), req.DisplayName)
	if err != nil {
		writeServiceError(w, err, "failed to create resource")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.CreateForNeedResponse{ResourceId: id.String()})
}
