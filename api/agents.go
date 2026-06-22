package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	agentssvc "github.com/airlockrun/airlock/service/agents"
	memberssvc "github.com/airlockrun/airlock/service/members"
	"github.com/go-chi/chi/v5"
)

// agentsHandler is the thin HTTP wrapper around agents.Service (plus
// members.Service for the /members sub-routes that still live on the
// same chi mount point).
type agentsHandler struct {
	svc          *agentssvc.Service
	members      *memberssvc.Service
	publicURL    string
	agentBaseURL func(slug string) string
}

func newAgentsHandler(svc *agentssvc.Service, members *memberssvc.Service, publicURL string, agentBaseURL func(slug string) string) *agentsHandler {
	if svc == nil {
		panic("api: agents.Service is required")
	}
	if members == nil {
		panic("api: members.Service is required")
	}
	if agentBaseURL == nil {
		panic("api: agentBaseURL func is required")
	}
	return &agentsHandler{svc: svc, members: members, publicURL: publicURL, agentBaseURL: agentBaseURL}
}

// writeAgentsError renders a service error using per-sentinel strings
// for the agent endpoints. Detail-wrapped errors surface their message
// via err.Error().
func writeAgentsError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	var msg string
	switch {
	case errors.Is(err, service.ErrInvalidInput), errors.Is(err, service.ErrConflict):
		if m := err.Error(); m != "invalid input" && m != "conflict" {
			msg = m
		} else if errors.Is(err, service.ErrConflict) {
			msg = "conflict"
		} else {
			msg = "invalid input"
		}
	case errors.Is(err, service.ErrUnauthorized):
		msg = "unauthorized"
	case errors.Is(err, service.ErrForbidden):
		// Detail wrap (e.g. "git credential does not belong to you") wins.
		if m := err.Error(); m != "forbidden" {
			msg = m
		} else {
			msg = "access denied"
		}
	case errors.Is(err, service.ErrNotFound):
		if m := err.Error(); m != "not found" {
			msg = m
		} else {
			msg = "agent not found"
		}
	default:
		msg = fallback
	}
	writeError(w, status, msg)
}

// Create handles POST /api/v1/agents.
func (h *agentsHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req airlockv1.CreateAgentRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	agent, err := h.svc.Create(r.Context(), p, agentssvc.CreateRequest{
		Name:             req.Name,
		Slug:             req.Slug,
		Description:      req.Description,
		BuildModel:       req.BuildModel,
		BuildProviderID:  req.BuildProviderId,
		ExecModel:        req.ExecModel,
		ExecProviderID:   req.ExecProviderId,
		Instructions:     req.Instructions,
		GitRemoteURL:     req.GitRemoteUrl,
		GitCredentialID:  req.GitCredentialId,
		GitDefaultBranch: req.GitDefaultBranch,
	})
	if err != nil {
		writeAgentsError(w, err, "failed to create agent")
		return
	}
	writeProto(w, http.StatusAccepted, &airlockv1.CreateAgentResponse{
		Agent: convert.AgentToProto(agent),
	})
}

// List handles GET /api/v1/agents.
func (h *agentsHandler) List(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	items, err := h.svc.List(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}
	out := make([]*airlockv1.AgentInfo, len(items))
	for i, it := range items {
		p := convert.AgentToProto(it.Agent)
		p.Running = it.Running
		p.YourAccess = string(it.YourAccess)
		p.OwnerName = it.OwnerName
		p.IsOwner = it.IsOwner
		out[i] = p
	}
	writeProto(w, http.StatusOK, &airlockv1.ListAgentsResponse{Agents: out})
}

// Get handles GET /api/v1/agents/{agentID}.
func (h *agentsHandler) Get(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	d, err := h.svc.Get(r.Context(), p, agentID)
	if err != nil {
		writeAgentsError(w, err, "failed to load agent")
		return
	}
	connInfos := make([]*airlockv1.ConnectionInfo, len(d.Connections))
	for i, c := range d.Connections {
		connInfos[i] = convert.ConnectionToProto(c, h.publicURL, agentID.String())
	}
	whInfos := make([]*airlockv1.WebhookInfo, len(d.Webhooks))
	for i, wh := range d.Webhooks {
		whInfos[i] = convert.WebhookToProto(wh, h.publicURL, agentID.String())
	}
	scheduleInfos := make([]*airlockv1.ScheduleInfo, len(d.Schedules))
	for i, c := range d.Schedules {
		scheduleInfos[i] = convert.ScheduleToProto(c)
	}
	routeInfos := make([]*airlockv1.RouteInfo, len(d.Routes))
	for i, route := range d.Routes {
		routeInfos[i] = convert.RouteToProto(route)
	}
	agentProto := convert.AgentToProto(d.Agent)
	agentProto.Running = d.Running
	agentProto.YourAccess = string(d.YourAccess)
	writeProto(w, http.StatusOK, &airlockv1.GetAgentDetailResponse{
		Agent:        agentProto,
		RouteBaseUrl: h.agentBaseURL(d.Agent.Slug),
		Connections:  connInfos,
		Webhooks:     whInfos,
		Schedules:    scheduleInfos,
		Routes:       routeInfos,
	})
}

// Update handles PATCH /api/v1/agents/{agentID}.
func (h *agentsHandler) Update(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	var req airlockv1.UpdateAgentRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	updated, err := h.svc.Update(r.Context(), p, agentID, agentssvc.UpdateRequest{
		Name:    req.Name,
		Slug:    req.Slug,
		AutoFix: req.AutoFix,
	})
	if err != nil {
		writeAgentsError(w, err, "failed to update agent")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.UpdateAgentResponse{
		Agent: convert.AgentToProto(updated),
	})
}

// Delete handles DELETE /api/v1/agents/{agentID}.
func (h *agentsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Delete(r.Context(), p, agentID); err != nil {
		writeAgentsError(w, err, "failed to delete agent")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Stop handles POST /api/v1/agents/{agentID}/stop.
func (h *agentsHandler) Stop(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Stop(r.Context(), p, agentID); err != nil {
		writeAgentsError(w, err, "failed to stop agent")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Start handles POST /api/v1/agents/{agentID}/start.
func (h *agentsHandler) Start(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Start(r.Context(), p, agentID); err != nil {
		writeAgentsError(w, err, "failed to start agent")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Suspend handles POST /api/v1/agents/{agentID}/suspend.
func (h *agentsHandler) Suspend(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Suspend(r.Context(), p, agentID); err != nil {
		writeAgentsError(w, err, "failed to suspend agent")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CancelBuild handles POST /api/v1/agents/{agentID}/builds/cancel.
func (h *agentsHandler) CancelBuild(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.CancelBuild(r.Context(), p, agentID); err != nil {
		writeAgentsError(w, err, "failed to cancel build")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Upgrade handles POST /api/v1/agents/{agentID}/upgrade.
func (h *agentsHandler) Upgrade(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	var req airlockv1.UpgradeAgentRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Upgrade(r.Context(), p, agentID, agentssvc.UpgradeRequest{
		RunID:       req.RunId,
		Description: req.Description,
	}); err != nil {
		writeAgentsError(w, err, "failed to upgrade agent")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// Rollback handles POST /api/v1/agents/{agentID}/rollback.
func (h *agentsHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	var req airlockv1.RollbackBuildRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Rollback(r.Context(), p, agentID, agentssvc.RollbackRequest{
		BuildID:        req.BuildId,
		ConversationID: req.ConversationId,
	}); err != nil {
		writeAgentsError(w, err, "failed to rollback agent")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// ListWebhooks handles GET /api/v1/agents/{agentID}/webhooks.
func (h *agentsHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.ListWebhooks(r.Context(), p, agentID)
	if err != nil {
		writeAgentsError(w, err, "failed to list webhooks")
		return
	}
	out := make([]*airlockv1.WebhookInfo, len(rows))
	for i, wh := range rows {
		out[i] = convert.WebhookToProto(wh, h.publicURL, agentID.String())
	}
	writeProto(w, http.StatusOK, &airlockv1.ListWebhooksResponse{Webhooks: out})
}

// ListSchedules handles GET /api/v1/agents/{agentID}/schedules.
func (h *agentsHandler) ListSchedules(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.ListSchedules(r.Context(), p, agentID)
	if err != nil {
		writeAgentsError(w, err, "failed to list schedules")
		return
	}
	out := make([]*airlockv1.ScheduleInfo, len(rows))
	for i, c := range rows {
		out[i] = convert.ScheduleToProto(c)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListSchedulesResponse{Schedules: out})
}

// ListTools handles GET /api/v1/agents/{agentID}/tools.
func (h *agentsHandler) ListTools(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	tools, err := h.svc.ListTools(r.Context(), p, agentID)
	if err != nil {
		writeAgentsError(w, err, "failed to list tools")
		return
	}
	out := make([]*airlockv1.ToolInfo, len(tools))
	for i, t := range tools {
		out[i] = convert.AgentToolToProto(t)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListToolsResponse{Tools: out})
}

// FireSchedule handles POST /api/v1/agents/{agentID}/schedules/{slug}/fire.
func (h *agentsHandler) FireSchedule(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	res, err := h.svc.FireSchedule(r.Context(), p, agentID, chi.URLParam(r, "slug"))
	if err != nil {
		writeAgentsError(w, err, "failed to fire schedule")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.FireScheduleResponse{RunId: res.RunID.String()})
}

// ListBuilds handles GET /api/v1/agents/{agentID}/builds.
func (h *agentsHandler) ListBuilds(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	builds, err := h.svc.ListBuilds(r.Context(), p, agentID)
	if err != nil {
		writeAgentsError(w, err, "failed to list builds")
		return
	}
	sourceRefByID := make(map[string]string, len(builds))
	for _, b := range builds {
		sourceRefByID[convert.PgUUIDToString(b.ID)] = b.SourceRef
	}
	out := make([]*airlockv1.AgentBuildInfo, len(builds))
	for i, b := range builds {
		var rollbackTargetSourceRef string
		if b.RollbackTargetID.Valid {
			rollbackTargetSourceRef = sourceRefByID[convert.PgUUIDToString(b.RollbackTargetID)]
		}
		out[i] = convert.AgentBuildListItemToProto(b, rollbackTargetSourceRef)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListAgentBuildsResponse{Builds: out})
}

// GetBuild handles GET /api/v1/agents/{agentID}/builds/{buildID}.
func (h *agentsHandler) GetBuild(w http.ResponseWriter, r *http.Request) {
	buildID, err := parseUUID(chi.URLParam(r, "buildID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid build ID")
		return
	}
	p := principalFromRequest(r)
	res, err := h.svc.GetBuild(r.Context(), p, buildID)
	if err != nil {
		writeAgentsError(w, err, "failed to load build")
		return
	}
	var rollbackTargetSourceRef string
	if res.Target != nil {
		rollbackTargetSourceRef = res.Target.SourceRef
	}
	writeProto(w, http.StatusOK, &airlockv1.GetAgentBuildResponse{
		Build: convert.AgentBuildDetailToProto(res.Build, rollbackTargetSourceRef),
	})
}

// --- members sub-routes (delegate to members.Service) ---

func writeMembersError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	var msg string
	switch {
	case memberssvc.IsCannotRemoveOwner(err):
		msg = "cannot remove the agent owner"
	case errors.Is(err, service.ErrUnauthorized):
		msg = "unauthorized"
	case errors.Is(err, service.ErrForbidden):
		msg = "agent admin access required"
	case errors.Is(err, service.ErrNotFound):
		msg = "agent not found"
	case errors.Is(err, service.ErrInvalidInput):
		msg = "invalid input"
	default:
		msg = fallback
	}
	writeError(w, status, msg)
}

// AddMember handles POST /api/v1/agents/{agentID}/members.
func (h *agentsHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	var req airlockv1.AddAgentMemberRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserId == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	targetID, err := parseUUID(req.UserId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	if err := h.members.Add(ctx, principalFromRequest(r), agentID, targetID, req.Role); err != nil {
		if errors.Is(err, service.ErrInvalidInput) {
			writeError(w, http.StatusBadRequest, "role must be 'admin' or 'user'")
			return
		}
		writeMembersError(w, err, "failed to add member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListMembers handles GET /api/v1/agents/{agentID}/members.
func (h *agentsHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	rows, err := h.members.List(r.Context(), p, agentID)
	if err != nil {
		writeMembersError(w, err, "failed to list members")
		return
	}
	out := make([]*airlockv1.AgentMemberInfo, len(rows))
	for i, m := range rows {
		out[i] = convert.MemberToProto(m)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListAgentMembersResponse{Members: out})
}

// RemoveMember handles DELETE /api/v1/agents/{agentID}/members/{userID}.
func (h *agentsHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	targetID, err := parseUUID(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	if err := h.members.Remove(ctx, principalFromRequest(r), agentID, targetID); err != nil {
		writeMembersError(w, err, "failed to remove member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
