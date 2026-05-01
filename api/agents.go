package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type agentsHandler struct {
	db          *db.DB
	builder     *builder.BuildService
	dispatcher  *trigger.Dispatcher
	encryptor   *crypto.Encryptor
	containers  container.ContainerManager
	promptProxy *trigger.PromptProxy
	publicURL   string
	logger      *zap.Logger
}

// Create handles POST /api/v1/agents.
func (h *agentsHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req airlockv1.CreateAgentRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Slug == "" {
		writeError(w, http.StatusBadRequest, "slug is required")
		return
	}

	userID := auth.UserIDFromContext(ctx)
	q := dbq.New(h.db.Pool())

	// Model overrides are optional at create time — empty strings mean the
	// agent inherits the current system default live. Validate format only
	// when a value is actually supplied.
	if req.BuildModel != "" && !strings.Contains(req.BuildModel, "/") {
		writeError(w, http.StatusBadRequest, "build_model must be in provider/model format")
		return
	}
	if req.ExecModel != "" && !strings.Contains(req.ExecModel, "/") {
		writeError(w, http.StatusBadRequest, "exec_model must be in provider/model format")
		return
	}

	// Create the agent record (status=draft) so we can return it immediately.
	// All model override columns default to '' (live inheritance).
	agent, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name:        req.Name,
		Slug:        req.Slug,
		UserID:      toPgUUID(userID),
		Description: req.Description,
		Config:      []byte("{}"),
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			writeError(w, http.StatusConflict, "agent slug already exists")
			return
		}
		h.logger.Error("create agent", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to create agent")
		return
	}

	// Persist explicit per-agent model overrides if the client supplied any.
	// Other capability columns stay empty and inherit from system_settings.
	if req.BuildModel != "" || req.ExecModel != "" {
		_ = q.UpdateAgentModels(ctx, dbq.UpdateAgentModelsParams{
			ID:         agent.ID,
			BuildModel: req.BuildModel,
			ExecModel:  req.ExecModel,
		})
		agent.BuildModel = req.BuildModel
		agent.ExecModel = req.ExecModel
	}

	// Auto-add creator as agent admin.
	_ = q.AddAgentMember(ctx, dbq.AddAgentMemberParams{
		AgentID: agent.ID,
		UserID:  toPgUUID(userID),
		Role:    "admin",
	})

	agentID := convert.PgUUIDToString(agent.ID)

	// Kick off build pipeline asynchronously. Build() logs success/failure
	// internally — no need to log the returned err here.
	go func() {
		_ = h.builder.Build(context.Background(), builder.BuildInput{
			AgentID:      agentID,
			Name:         req.Name,
			Slug:         req.Slug,
			UserID:       userID.String(),
			BuildModel:   req.BuildModel,
			Instructions: req.Instructions,
		})
	}()

	writeProto(w, http.StatusAccepted, &airlockv1.CreateAgentResponse{
		Agent: agentToProto(agent),
	})
}

// List handles GET /api/v1/agents.
func (h *agentsHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.ClaimsFromContext(ctx)
	q := dbq.New(h.db.Pool())

	var agents []dbq.Agent
	var err error

	if auth.RoleAtLeast(claims.TenantRole, "admin") {
		agents, err = q.ListAgents(ctx)
	} else {
		agents, err = q.ListAgentsByUserID(ctx, toPgUUID(auth.UserIDFromContext(ctx)))
	}
	if err != nil {
		h.logger.Error("list agents", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}

	out := make([]*airlockv1.AgentInfo, len(agents))
	for i, a := range agents {
		out[i] = agentToProto(a)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListAgentsResponse{Agents: out})
}

// Get handles GET /api/v1/agents/{agentID} — rich detail.
func (h *agentsHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	pgID := toPgUUID(agentID)

	agent, err := q.GetAgentByID(ctx, pgID)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	if err := h.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// Load connections with credential status.
	conns, _ := q.ListConnectionsByAgent(ctx, pgID)
	connInfos := make([]*airlockv1.ConnectionInfo, len(conns))
	for i, c := range conns {
		connInfos[i] = connectionToProto(c, h.publicURL, agentID.String())
	}

	// Load webhooks.
	webhooks, _ := q.ListWebhooksByAgentWithStatus(ctx, pgID)
	whInfos := make([]*airlockv1.WebhookInfo, len(webhooks))
	for i, wh := range webhooks {
		whInfos[i] = webhookToProto(wh, h.publicURL, agentID.String())
	}

	// Load crons.
	crons, _ := q.ListCronsByAgent(ctx, pgID)
	cronInfos := make([]*airlockv1.CronInfo, len(crons))
	for i, c := range crons {
		cronInfos[i] = cronToProto(c)
	}

	// Load routes.
	routes, _ := q.ListRoutesByAgent(ctx, pgID)
	routeInfos := make([]*airlockv1.RouteInfo, len(routes))
	for i, r := range routes {
		routeInfos[i] = routeToProto(r)
	}

	writeProto(w, http.StatusOK, &airlockv1.GetAgentDetailResponse{
		Agent:       agentToProto(agent),
		Connections: connInfos,
		Webhooks:    whInfos,
		Crons:       cronInfos,
		Routes:      routeInfos,
	})
}

// Update handles PATCH /api/v1/agents/{agentID}.
func (h *agentsHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	q := dbq.New(h.db.Pool())

	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// Resolve auto_fix: if not provided in request, keep existing value.
	autoFix := agent.AutoFix
	if req.AutoFix != nil {
		autoFix = *req.AutoFix
	}
	updated, err := q.UpdateAgentFields(ctx, dbq.UpdateAgentFieldsParams{
		ID:      toPgUUID(agentID),
		AutoFix: autoFix,
	})
	if err != nil {
		h.logger.Error("update agent", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to update agent")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.UpdateAgentResponse{
		Agent: agentToProto(updated),
	})
}

// Delete handles DELETE /api/v1/agents/{agentID}.
func (h *agentsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())

	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// Cancel any in-flight build/upgrade and wait for its toolserver to
	// die — otherwise the upgrade goroutine keeps writing into the
	// workspace dir we're about to rm and the agent_builds row we're
	// about to CASCADE delete, producing FK errors and orphan files.
	// 30s covers worst-case Docker SIGKILL + last DB write; on timeout
	// we proceed anyway (the leftover writes are harmless once the
	// agent row is gone).
	if h.builder != nil {
		h.builder.CancelBuildAndWait(agentID.String(), 30*time.Second)
	}

	// Stop container (best effort).
	if h.containers != nil {
		containerName := "airlock-agent-" + agentID.String()[:8]
		_ = h.containers.StopAgent(ctx, containerName)
	}

	// Remove Docker image (best effort).
	if h.containers != nil && agent.ImageRef != "" {
		_ = h.containers.RemoveImage(ctx, agent.ImageRef)
	}

	// Drop agent schema and role (best effort).
	schemaName := "agent_" + strings.ReplaceAll(agentID.String(), "-", "")
	conn, err := h.db.Pool().Acquire(ctx)
	if err == nil {
		conn.Exec(ctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schemaName))
		conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", schemaName))
		conn.Release()
	}

	// Remove agent code from monorepo (best effort).
	if h.builder != nil {
		if err := builder.RemoveAgentCode(h.builder.MonorepoPath(), agentID.String()); err != nil {
			h.logger.Warn("remove agent code", zap.Error(err))
		}
	}

	// Delete agent record (CASCADE handles connections, webhooks, crons, runs, conversations).
	if err := q.DeleteAgent(ctx, toPgUUID(agentID)); err != nil {
		h.logger.Error("delete agent", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to delete agent")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Stop handles POST /api/v1/agents/{agentID}/stop.
func (h *agentsHandler) Stop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	containerName := "airlock-agent-" + agentID.String()[:8]
	if err := h.containers.StopAgent(ctx, containerName); err != nil {
		h.logger.Error("stop agent", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to stop agent")
		return
	}

	_ = q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{
		ID:     toPgUUID(agentID),
		Status: "stopped",
	})

	w.WriteHeader(http.StatusNoContent)
}

// Start handles POST /api/v1/agents/{agentID}/start.
func (h *agentsHandler) Start(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	if agent.ImageRef == "" {
		writeError(w, http.StatusBadRequest, "agent has no image — build it first")
		return
	}

	// Start the container eagerly.
	if _, err := h.dispatcher.EnsureRunning(ctx, agentID); err != nil {
		h.logger.Error("start agent", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to start agent")
		return
	}

	_ = q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{
		ID:     toPgUUID(agentID),
		Status: "active",
	})

	w.WriteHeader(http.StatusNoContent)
}

// CancelBuild handles POST /api/v1/agents/{agentID}/builds/cancel.
func (h *agentsHandler) CancelBuild(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	if !h.builder.CancelBuild(agentID.String()) {
		writeError(w, http.StatusConflict, "no build in progress")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Upgrade handles POST /api/v1/agents/{agentID}/upgrade.
func (h *agentsHandler) Upgrade(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// If the agent was never successfully built (no image), retry the full build
	// pipeline instead of the upgrade pipeline.
	if agent.ImageRef == "" {
		go func() {
			// Build() logs success/failure internally.
			_ = h.builder.Build(context.Background(), builder.BuildInput{
				AgentID:    agentID.String(),
				Name:       agent.Name,
				Slug:       agent.Slug,
				UserID:     convert.PgUUIDToString(agent.UserID),
				BuildModel: agent.BuildModel,
			})
		}()
	} else {
		go func() {
			runID := req.RunId
			if runID == "" {
				runID = uuid.New().String()
			}
			input := builder.UpgradeInput{
				AgentID:     agentID.String(),
				RunID:       runID,
				Reason:      "manual",
				Description: req.Description,
			}
			// If a run ID was provided, load full error context from that run.
			if req.RunId != "" {
				if runUUID, err := parseUUID(req.RunId); err == nil {
					pgRunID := toPgUUID(runUUID)
					if failedRun, err := q.GetRunByID(context.Background(), pgRunID); err == nil {
						input.Reason = "auto_fix"
						input.ErrorMessage = failedRun.ErrorMessage
						input.PanicTrace = failedRun.PanicTrace
						input.InputPayload = string(failedRun.InputPayload)
						input.Actions = string(failedRun.Actions)
						// Load conversation messages for this run.
						if msgs, err := q.ListMessagesByRun(context.Background(), pgRunID); err == nil {
							var msgSummaries []string
							for _, m := range msgs {
								msgSummaries = append(msgSummaries, fmt.Sprintf("[%s] %s", m.Role, m.Content))
							}
							input.Messages = strings.Join(msgSummaries, "\n")
						}
					}
				}
			}
			if err := h.builder.AcquireUpgradeLock(context.Background(), agentID.String()); err != nil {
				if !errors.Is(err, builder.ErrUpgradeInProgress) {
					h.logger.Error("upgrade lock failed", zap.String("agent", agentID.String()), zap.Error(err))
				}
				return
			}
			h.builder.RunUpgrade(context.Background(), input)
		}()
	}

	w.WriteHeader(http.StatusAccepted)
}

// ListWebhooks handles GET /api/v1/agents/{agentID}/webhooks.
func (h *agentsHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	webhooks, err := q.ListWebhooksByAgentWithStatus(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list webhooks", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list webhooks")
		return
	}

	out := make([]*airlockv1.WebhookInfo, len(webhooks))
	for i, wh := range webhooks {
		out[i] = webhookToProto(wh, h.publicURL, agentID.String())
	}
	writeProto(w, http.StatusOK, &airlockv1.ListWebhooksResponse{Webhooks: out})
}

// ListCrons handles GET /api/v1/agents/{agentID}/crons.
func (h *agentsHandler) ListCrons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	crons, err := q.ListCronsByAgent(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list crons", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list crons")
		return
	}

	out := make([]*airlockv1.CronInfo, len(crons))
	for i, c := range crons {
		out[i] = cronToProto(c)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListCronsResponse{Crons: out})
}

// ListTools handles GET /api/v1/agents/{agentID}/tools.
func (h *agentsHandler) ListTools(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	tools, err := q.ListAgentTools(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list tools", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list tools")
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
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	cronName := chi.URLParam(r, "name")

	// Look up cron timeout.
	q := dbq.New(h.db.Pool())
	cron, err := q.GetCronByAgentAndName(ctx, dbq.GetCronByAgentAndNameParams{
		AgentID: toPgUUID(agentID),
		Name:    cronName,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "cron not found")
		return
	}
	timeout := time.Duration(cron.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Minute
	}

	rc, runID, err := h.dispatcher.ForwardCron(ctx, agentID, cronName, timeout)
	if err != nil {
		h.logger.Error("fire cron", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to fire cron")
		return
	}
	io.Copy(io.Discard, rc)
	rc.Close()

	writeProto(w, http.StatusOK, &airlockv1.FireCronResponse{
		RunId: runID.String(),
	})
}

// --- helpers ---

// requireAccess checks if the current user has access to the agent via agent_members.
func (h *agentsHandler) requireAccess(ctx context.Context, agent dbq.Agent) error {
	userID := auth.UserIDFromContext(ctx)
	q := dbq.New(h.db.Pool())
	has, err := q.HasAgentAccess(ctx, dbq.HasAgentAccessParams{
		AgentID: agent.ID,
		UserID:  toPgUUID(userID),
	})
	if err != nil {
		return fmt.Errorf("check access: %w", err)
	}
	if !has {
		return fmt.Errorf("access denied")
	}
	return nil
}

// requireAgentAdmin checks if the current user has admin role on the agent.
func (h *agentsHandler) requireAgentAdmin(ctx context.Context, agentID pgtype.UUID) error {
	userID := auth.UserIDFromContext(ctx)
	q := dbq.New(h.db.Pool())
	member, err := q.GetAgentMember(ctx, dbq.GetAgentMemberParams{
		AgentID: agentID,
		UserID:  toPgUUID(userID),
	})
	if err != nil {
		return fmt.Errorf("access denied")
	}
	if member.Role != "admin" {
		return fmt.Errorf("admin access required")
	}
	return nil
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
	if req.Role != "admin" && req.Role != "user" {
		writeError(w, http.StatusBadRequest, "role must be 'admin' or 'user'")
		return
	}

	pgAgentID := toPgUUID(agentID)

	// System admins can add themselves to any agent. Agent admins can add anyone.
	claims := auth.ClaimsFromContext(ctx)
	callerID := auth.UserIDFromContext(ctx)
	targetID, err := parseUUID(req.UserId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	isSysAdmin := auth.RoleAtLeast(claims.TenantRole, "admin")
	isSelfAdd := callerID == targetID

	if isSysAdmin && isSelfAdd {
		// System admin adding themselves — always allowed
	} else if err := h.requireAgentAdmin(ctx, pgAgentID); err != nil {
		writeError(w, http.StatusForbidden, "agent admin access required")
		return
	}

	q := dbq.New(h.db.Pool())
	if err := q.AddAgentMember(ctx, dbq.AddAgentMemberParams{
		AgentID: pgAgentID,
		UserID:  toPgUUID(targetID),
		Role:    req.Role,
	}); err != nil {
		h.logger.Error("add agent member", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to add member")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListMembers handles GET /api/v1/agents/{agentID}/members.
func (h *agentsHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	members, err := q.ListAgentMembers(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list agent members", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list members")
		return
	}

	out := make([]*airlockv1.AgentMemberInfo, len(members))
	for i, m := range members {
		out[i] = &airlockv1.AgentMemberInfo{
			UserId:      convert.PgUUIDToString(m.UserID),
			Email:       m.Email,
			DisplayName: m.DisplayName,
			Role:        m.Role,
			CreatedAt:   convert.PgTimestampToProto(m.CreatedAt),
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

	pgAgentID := toPgUUID(agentID)
	if err := h.requireAgentAdmin(ctx, pgAgentID); err != nil {
		writeError(w, http.StatusForbidden, "agent admin access required")
		return
	}

	// Prevent removing the agent owner.
	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgAgentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if pgUUID(agent.UserID) == targetID {
		writeError(w, http.StatusBadRequest, "cannot remove the agent owner")
		return
	}

	if err := q.RemoveAgentMember(ctx, dbq.RemoveAgentMemberParams{
		AgentID: pgAgentID,
		UserID:  toPgUUID(targetID),
	}); err != nil {
		h.logger.Error("remove agent member", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to remove member")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func agentToProto(a dbq.Agent) *airlockv1.AgentInfo {
	return &airlockv1.AgentInfo{
		Id:            convert.PgUUIDToString(a.ID),
		Name:          a.Name,
		Slug:          a.Slug,
		Description:   a.Description,
		Status:        a.Status,
		UpgradeStatus: a.UpgradeStatus,
		AutoFix:       a.AutoFix,
		ErrorMessage:  a.ErrorMessage,
		CreatedAt:     convert.PgTimestampToProto(a.CreatedAt),
		UpdatedAt:     convert.PgTimestampToProto(a.UpdatedAt),
		BuildModel:    a.BuildModel,
		ExecModel:     a.ExecModel,
	}
}

func connectionToProto(c dbq.Connection, publicURL, agentID string) *airlockv1.ConnectionInfo {
	authorized := c.Credentials != ""
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
	}
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

// ListBuilds handles GET /api/v1/agents/{agentID}/builds.
func (h *agentsHandler) ListBuilds(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	builds, err := q.ListAgentBuildsByAgent(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list builds", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list builds")
		return
	}

	out := make([]*airlockv1.AgentBuildInfo, len(builds))
	for i, b := range builds {
		out[i] = &airlockv1.AgentBuildInfo{
			Id:           convert.PgUUIDToString(b.ID),
			AgentId:      convert.PgUUIDToString(b.AgentID),
			Type:         b.Type,
			Status:       b.Status,
			Instructions: b.Instructions,
			ErrorMessage: b.ErrorMessage,
			SourceRef:    b.SourceRef,
			ImageRef:     b.ImageRef,
			StartedAt:    convert.PgTimestampToProto(b.StartedAt),
			FinishedAt:   convert.PgTimestampToProto(b.FinishedAt),
		}
	}

	writeProto(w, http.StatusOK, &airlockv1.ListAgentBuildsResponse{Builds: out})
}

// GetBuild handles GET /api/v1/agents/{agentID}/builds/{buildID}.
func (h *agentsHandler) GetBuild(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	buildID, err := parseUUID(chi.URLParam(r, "buildID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid build ID")
		return
	}

	q := dbq.New(h.db.Pool())
	b, err := q.GetAgentBuild(ctx, toPgUUID(buildID))
	if err != nil {
		writeError(w, http.StatusNotFound, "build not found")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.GetAgentBuildResponse{
		Build: &airlockv1.AgentBuildInfo{
			Id:           convert.PgUUIDToString(b.ID),
			AgentId:      convert.PgUUIDToString(b.AgentID),
			Type:         b.Type,
			Status:       b.Status,
			Instructions: b.Instructions,
			SolLog:       b.SolLog,
			DockerLog:    b.DockerLog,
			ErrorMessage: b.ErrorMessage,
			SourceRef:    b.SourceRef,
			ImageRef:     b.ImageRef,
			StartedAt:    convert.PgTimestampToProto(b.StartedAt),
			FinishedAt:   convert.PgTimestampToProto(b.FinishedAt),
			LogSeq:       b.LogSeq,
		},
	})
}