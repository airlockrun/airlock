package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	agentssvc "github.com/airlockrun/airlock/service/agents"
	memberssvc "github.com/airlockrun/airlock/service/members"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
		Agent: agentToProto(agent),
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
		p := agentToProto(it.Agent)
		p.Running = it.Running
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
		connInfos[i] = connectionToProto(c, h.publicURL, agentID.String())
	}
	whInfos := make([]*airlockv1.WebhookInfo, len(d.Webhooks))
	for i, wh := range d.Webhooks {
		whInfos[i] = webhookToProto(wh, h.publicURL, agentID.String())
	}
	cronInfos := make([]*airlockv1.CronInfo, len(d.Crons))
	for i, c := range d.Crons {
		cronInfos[i] = cronToProto(c)
	}
	routeInfos := make([]*airlockv1.RouteInfo, len(d.Routes))
	for i, route := range d.Routes {
		routeInfos[i] = routeToProto(route)
	}
	agentProto := agentToProto(d.Agent)
	agentProto.Running = d.Running
	writeProto(w, http.StatusOK, &airlockv1.GetAgentDetailResponse{
		Agent:        agentProto,
		RouteBaseUrl: h.agentBaseURL(d.Agent.Slug),
		Connections:  connInfos,
		Webhooks:     whInfos,
		Crons:        cronInfos,
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
		Agent: agentToProto(updated),
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
		out[i] = webhookToProto(wh, h.publicURL, agentID.String())
	}
	writeProto(w, http.StatusOK, &airlockv1.ListWebhooksResponse{Webhooks: out})
}

// ListCrons handles GET /api/v1/agents/{agentID}/crons.
func (h *agentsHandler) ListCrons(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.ListCrons(r.Context(), p, agentID)
	if err != nil {
		writeAgentsError(w, err, "failed to list crons")
		return
	}
	out := make([]*airlockv1.CronInfo, len(rows))
	for i, c := range rows {
		out[i] = cronToProto(c)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListCronsResponse{Crons: out})
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
		out[i] = &airlockv1.ToolInfo{
			Id:           pgUUID(t.ID).String(),
			Name:         t.Name,
			Description:  t.Description,
			Access:       t.Access,
			InputSchema:  string(t.InputSchema),
			OutputSchema: string(t.OutputSchema),
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListToolsResponse{Tools: out})
}

// FireCron handles POST /api/v1/agents/{agentID}/crons/{name}/fire.
func (h *agentsHandler) FireCron(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	res, err := h.svc.FireCron(r.Context(), p, agentID, chi.URLParam(r, "name"))
	if err != nil {
		writeAgentsError(w, err, "failed to fire cron")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.FireCronResponse{RunId: res.RunID.String()})
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
		var rollbackTargetID, rollbackTargetSourceRef string
		if b.RollbackTargetID.Valid {
			rollbackTargetID = convert.PgUUIDToString(b.RollbackTargetID)
			rollbackTargetSourceRef = sourceRefByID[rollbackTargetID]
		}
		out[i] = &airlockv1.AgentBuildInfo{
			Id:                      convert.PgUUIDToString(b.ID),
			AgentId:                 convert.PgUUIDToString(b.AgentID),
			Type:                    b.Type,
			Status:                  b.Status,
			Instructions:            b.Instructions,
			ErrorMessage:            b.ErrorMessage,
			SourceRef:               b.SourceRef,
			ImageRef:                b.ImageRef,
			StartedAt:               convert.PgTimestampToProto(b.StartedAt),
			FinishedAt:              convert.PgTimestampToProto(b.FinishedAt),
			LlmCalls:                b.LlmCalls,
			LlmTokensIn:             b.LlmTokensIn,
			LlmTokensOut:            b.LlmTokensOut,
			LlmCostEstimate:         b.LlmCostEstimate,
			RollbackTargetId:        rollbackTargetID,
			RollbackTargetSourceRef: rollbackTargetSourceRef,
			SdkVersion:              b.SdkVersion,
		}
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
	b := res.Build
	var rollbackTargetID, rollbackTargetSourceRef string
	if b.RollbackTargetID.Valid {
		rollbackTargetID = convert.PgUUIDToString(b.RollbackTargetID)
		if res.Target != nil {
			rollbackTargetSourceRef = res.Target.SourceRef
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.GetAgentBuildResponse{
		Build: &airlockv1.AgentBuildInfo{
			Id:                      convert.PgUUIDToString(b.ID),
			AgentId:                 convert.PgUUIDToString(b.AgentID),
			Type:                    b.Type,
			Status:                  b.Status,
			Instructions:            b.Instructions,
			SolLog:                  b.SolLog,
			DockerLog:               b.DockerLog,
			ErrorMessage:            b.ErrorMessage,
			SourceRef:               b.SourceRef,
			ImageRef:                b.ImageRef,
			StartedAt:               convert.PgTimestampToProto(b.StartedAt),
			FinishedAt:              convert.PgTimestampToProto(b.FinishedAt),
			LogSeq:                  b.LogSeq,
			LlmCalls:                b.LlmCalls,
			LlmTokensIn:             b.LlmTokensIn,
			LlmTokensOut:            b.LlmTokensOut,
			LlmCostEstimate:         b.LlmCostEstimate,
			RollbackTargetId:        rollbackTargetID,
			RollbackTargetSourceRef: rollbackTargetSourceRef,
			SdkVersion:              b.SdkVersion,
		},
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
		out[i] = &airlockv1.AgentMemberInfo{
			UserId:      m.UserID.String(),
			Email:       m.Email,
			DisplayName: m.DisplayName,
			Role:        m.Role,
			CreatedAt:   convert.PgTimestampToProto(pgtype.Timestamptz{Time: m.CreatedAt, Valid: !m.CreatedAt.IsZero()}),
		}
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

// --- proto helpers (still used by other handlers in the api package) ---

func agentToProto(a dbq.Agent) *airlockv1.AgentInfo {
	return &airlockv1.AgentInfo{
		Id:              convert.PgUUIDToString(a.ID),
		Name:            a.Name,
		Slug:            a.Slug,
		Description:     a.Description,
		Emoji:           a.Emoji,
		Status:          a.Status,
		UpgradeStatus:   a.UpgradeStatus,
		AutoFix:         a.AutoFix,
		ErrorMessage:    a.ErrorMessage,
		CreatedAt:       convert.PgTimestampToProto(a.CreatedAt),
		UpdatedAt:       convert.PgTimestampToProto(a.UpdatedAt),
		BuildModel:      a.BuildModel,
		ExecModel:       a.ExecModel,
		BuildProviderId: convert.PgUUIDToString(a.BuildProviderID),
		ExecProviderId:  convert.PgUUIDToString(a.ExecProviderID),
	}
}

func connectionToProto(c dbq.Connection, publicURL, agentID string) *airlockv1.ConnectionInfo {
	authorized := c.AccessTokenRef != ""
	hasOAuthApp := c.ClientID != "" && c.ClientSecret != ""

	var authURL string
	if c.AuthMode == "oauth" {
		authURL = fmt.Sprintf("%s/api/v1/credentials/oauth/start?agent_id=%s&slug=%s", publicURL, agentID, c.Slug)
	} else if c.AuthMode == "token" {
		authURL = fmt.Sprintf("%s/ui/credentials/new?agent_id=%s&slug=%s", publicURL, agentID, c.Slug)
	}

	return &airlockv1.ConnectionInfo{
		Id:                convert.PgUUIDToString(c.ID),
		Slug:              c.Slug,
		Name:              c.Name,
		Description:       c.Description,
		AuthMode:          c.AuthMode,
		Authorized:        authorized,
		HasOauthApp:       hasOAuthApp,
		SetupInstructions: c.SetupInstructions,
		AuthUrl:           authURL,
		TokenExpiresAt:    convert.PgTimestampToProto(c.TokenExpiresAt),
		Warnings:          connectionWarnings(c.AuthMode, authorized, c.RefreshToken != "", c.TokenExpiresAt),
	}
}

func connectionWarnings(authMode string, authorized, hasRefreshToken bool, tokenExpiresAt pgtype.Timestamptz) []string {
	if authMode != "oauth" || !authorized {
		return nil
	}
	var warnings []string
	if !hasRefreshToken {
		warnings = append(warnings, "No refresh token — this connection will stop working once its access token expires. Re-authorize to fix.")
	}
	if tokenExpiresAt.Valid && tokenExpiresAt.Time.Before(time.Now()) {
		warnings = append(warnings, "Authorization has expired — re-authorize.")
	}
	return warnings
}

func webhookToProto(wh dbq.ListWebhooksByAgentWithStatusRow, publicURL, agentID string) *airlockv1.WebhookInfo {
	publicURLFull := fmt.Sprintf("%s/webhooks/%s/%s", publicURL, agentID, wh.Path)

	var secretMasked string
	if wh.Secret != "" && len(wh.Secret) > 8 {
		secretMasked = wh.Secret[:4] + "..." + wh.Secret[len(wh.Secret)-4:]
	} else if wh.Secret != "" {
		secretMasked = "***"
	}

	return &airlockv1.WebhookInfo{
		Id:             convert.PgUUIDToString(wh.ID),
		Path:           wh.Path,
		VerifyMode:     wh.VerifyMode,
		PublicUrl:      publicURLFull,
		SecretMasked:   secretMasked,
		LastReceivedAt: convert.PgTimestampToProto(wh.LastReceivedAt),
		CreatedAt:      convert.PgTimestampToProto(wh.CreatedAt),
		Description:    wh.Description,
	}
}

func cronToProto(c dbq.AgentCron) *airlockv1.CronInfo {
	return &airlockv1.CronInfo{
		Id:          convert.PgUUIDToString(c.ID),
		Name:        c.Name,
		Schedule:    c.Schedule,
		LastFiredAt: convert.PgTimestampToProto(c.LastFiredAt),
		CreatedAt:   convert.PgTimestampToProto(c.CreatedAt),
		Description: c.Description,
	}
}

func routeToProto(r dbq.AgentRoute) *airlockv1.RouteInfo {
	return &airlockv1.RouteInfo{
		Id:          convert.PgUUIDToString(r.ID),
		Path:        r.Path,
		Method:      r.Method,
		Access:      r.Access,
		Description: r.Description,
	}
}
