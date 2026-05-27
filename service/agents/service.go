// Package agents owns the agent-lifecycle business logic: create,
// configure, build/upgrade/rollback, start/stop/suspend, list/get
// detail, and the per-agent git-remote bindings.
package agents

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// BridgeStopper is the subset of *trigger.BridgeManager Delete uses.
type BridgeStopper interface {
	RemoveBridge(id uuid.UUID)
}

type Service struct {
	db         *db.DB
	builder    *builder.BuildService
	dispatcher *trigger.Dispatcher
	containers container.ContainerManager
	bridgeMgr  BridgeStopper
	logger     *zap.Logger
}

func New(d *db.DB, build *builder.BuildService, dispatcher *trigger.Dispatcher, containers container.ContainerManager, bridgeMgr BridgeStopper, logger *zap.Logger) *Service {
	if d == nil {
		panic("agents: db is required")
	}
	if build == nil {
		panic("agents: builder is required")
	}
	if dispatcher == nil {
		panic("agents: dispatcher is required")
	}
	if containers == nil {
		panic("agents: container manager is required")
	}
	if bridgeMgr == nil {
		panic("agents: bridge manager is required")
	}
	if logger == nil {
		panic("agents: logger is required")
	}
	return &Service{
		db: d, builder: build, dispatcher: dispatcher,
		containers: containers, bridgeMgr: bridgeMgr, logger: logger,
	}
}

// --- types ---

// CreateRequest is the input to Create — mirrors CreateAgentRequest but
// in plain Go.
type CreateRequest struct {
	Name             string
	Slug             string
	Description      string
	BuildModel       string
	BuildProviderID  string
	ExecModel        string
	ExecProviderID   string
	Instructions     string
	GitRemoteURL     string
	GitCredentialID  string
	GitDefaultBranch string
}

// UpdateRequest mirrors UpdateAgentRequest. Pointer fields express
// "unset → keep existing".
type UpdateRequest struct {
	Name    *string
	Slug    *string
	AutoFix *bool
}

// ListItem is one row from List plus the live container-running flag.
type ListItem struct {
	Agent   dbq.Agent
	Running bool
}

// Detail is the Get response payload — the agent plus the per-agent
// resource lists the agent-detail page renders.
type Detail struct {
	Agent       dbq.Agent
	Running     bool
	Connections []dbq.Connection
	Webhooks    []dbq.ListWebhooksByAgentWithStatusRow
	Crons       []dbq.AgentCron
	Routes      []dbq.AgentRoute
}

// FireCronResult is the output of FireCron — the run ID for the SPA to
// subscribe to.
type FireCronResult struct {
	RunID uuid.UUID
}

// GitConfig is the read-side view of the agent's external git binding.
type GitConfig struct {
	RemoteURL      string
	CredentialID   string // empty when not connected
	CredentialName string
	DefaultBranch  string
	WebhookSecret  string
	LastSyncedRef  string
}

// ConnectGitRequest is the input to ConnectGit.
type ConnectGitRequest struct {
	RemoteURL     string
	CredentialID  string
	DefaultBranch string
}

// --- helpers ---

var agentSlugRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func validAgentSlug(s string) bool {
	if len(s) < 2 || len(s) > 63 {
		return false
	}
	return agentSlugRe.MatchString(s)
}

func parseOptionalProviderID(s string) (pgtype.UUID, error) {
	if s == "" {
		return pgtype.UUID{}, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: id, Valid: true}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// requireAccess fails-with-ErrForbidden when caller isn't a member,
// fails-with-ErrUnauthorized when no userID is in ctx. Used by the
// "any member can do this" endpoints.
func (s *Service) requireAccess(ctx context.Context, q *dbq.Queries, userID, agentID uuid.UUID) error {
	if userID == uuid.Nil {
		return service.ErrUnauthorized
	}
	has, err := q.HasAgentAccess(ctx, dbq.HasAgentAccessParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
		UserID:  pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("check access: %w", err)
	}
	if !has {
		return service.ErrForbidden
	}
	return nil
}

// requireAdmin matches the agents.go gate exactly: agent_members.role == "admin".
func (s *Service) requireAdmin(ctx context.Context, q *dbq.Queries, userID, agentID uuid.UUID) error {
	if userID == uuid.Nil {
		return service.ErrUnauthorized
	}
	member, err := q.GetAgentMember(ctx, dbq.GetAgentMemberParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
		UserID:  pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return service.ErrForbidden
	}
	if member.Role != "admin" {
		return service.ErrForbidden
	}
	return nil
}

// broadcastSiblingChange triggers a /refresh on every active agent
// except changedAgentID — used after create/update/delete so peer agents
// pick up the new agent_<slug> binding without restarting.
func (s *Service) broadcastSiblingChange(ctx context.Context, changedAgentID uuid.UUID) {
	q := dbq.New(s.db.Pool())
	rows, err := q.ListActiveAgentIDs(ctx)
	if err != nil {
		s.logger.Error("broadcast: list active agents", zap.Error(err))
		return
	}
	var wg sync.WaitGroup
	for _, r := range rows {
		id := uuid.UUID(r.Bytes)
		if id == changedAgentID {
			continue
		}
		wg.Add(1)
		go func(target uuid.UUID) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := s.dispatcher.RefreshAgent(rctx, target); err != nil {
				s.logger.Warn("broadcast: refresh failed",
					zap.String("agent_id", target.String()), zap.Error(err))
			}
		}(id)
	}
	wg.Wait()
}

// --- methods ---

// Create creates an agent row (status=draft), records explicit per-agent
// model overrides if provided, auto-adds the creator as agent-admin, and
// kicks off the async build pipeline. Returns the freshly-inserted row;
// the build runs in a background goroutine and reports state via
// agent_builds + the runtime WebSocket.
func (s *Service) Create(ctx context.Context, userID uuid.UUID, req CreateRequest) (dbq.Agent, error) {
	if userID == uuid.Nil {
		return dbq.Agent{}, service.ErrUnauthorized
	}
	if req.Name == "" {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "name is required")
	}
	if req.Slug == "" {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "slug is required")
	}
	q := dbq.New(s.db.Pool())
	buildProviderFK, err := parseOptionalProviderID(req.BuildProviderID)
	if err != nil {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "invalid build_provider_id: %s", err.Error())
	}
	if (req.BuildModel != "") != buildProviderFK.Valid {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "build_model and build_provider_id must be set or unset together")
	}
	execProviderFK, err := parseOptionalProviderID(req.ExecProviderID)
	if err != nil {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "invalid exec_provider_id: %s", err.Error())
	}
	if (req.ExecModel != "") != execProviderFK.Valid {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "exec_model and exec_provider_id must be set or unset together")
	}
	var gitCredFK pgtype.UUID
	if req.GitRemoteURL != "" {
		if req.GitCredentialID == "" {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "git_credential_id is required when git_remote_url is set")
		}
		credID, err := uuid.Parse(req.GitCredentialID)
		if err != nil {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "invalid git_credential_id")
		}
		cred, err := q.GetGitCredential(ctx, pgtype.UUID{Bytes: credID, Valid: true})
		if err != nil {
			return dbq.Agent{}, service.Detail(service.ErrNotFound, "git credential not found")
		}
		if uuid.UUID(cred.UserID.Bytes) != userID {
			return dbq.Agent{}, service.Detail(service.ErrForbidden, "git credential does not belong to you")
		}
		gitCredFK = pgtype.UUID{Bytes: credID, Valid: true}
	}
	agent, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name:        req.Name,
		Slug:        req.Slug,
		UserID:      pgtype.UUID{Bytes: userID, Valid: true},
		Description: req.Description,
		Config:      []byte("{}"),
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return dbq.Agent{}, service.Detail(service.ErrConflict, "agent slug already exists")
		}
		s.logger.Error("create agent", zap.Error(err))
		return dbq.Agent{}, err
	}
	if req.BuildModel != "" || req.ExecModel != "" {
		_ = q.UpdateAgentModels(ctx, dbq.UpdateAgentModelsParams{
			ID:              agent.ID,
			BuildProviderID: buildProviderFK,
			BuildModel:      req.BuildModel,
			ExecProviderID:  execProviderFK,
			ExecModel:       req.ExecModel,
		})
		agent.BuildProviderID = buildProviderFK
		agent.BuildModel = req.BuildModel
		agent.ExecProviderID = execProviderFK
		agent.ExecModel = req.ExecModel
	}
	_ = q.AddAgentMember(ctx, dbq.AddAgentMemberParams{
		AgentID: agent.ID,
		UserID:  pgtype.UUID{Bytes: userID, Valid: true},
		Role:    "admin",
	})
	agentIDStr := uuid.UUID(agent.ID.Bytes).String()
	go func() {
		_ = s.builder.Build(context.Background(), builder.BuildInput{
			AgentID:          agentIDStr,
			Name:             req.Name,
			Slug:             req.Slug,
			UserID:           userID.String(),
			BuildProviderID:  buildProviderFK,
			BuildModel:       req.BuildModel,
			Instructions:     req.Instructions,
			GitRemoteURL:     req.GitRemoteURL,
			GitCredentialID:  gitCredFK,
			GitDefaultBranch: req.GitDefaultBranch,
		})
	}()
	return agent, nil
}

// List returns the agents visible to the caller — every agent for
// tenant admins, agent_members-joined for everyone else — annotated
// with the live container-running flag.
func (s *Service) List(ctx context.Context, userID uuid.UUID, tenantRole string) ([]ListItem, error) {
	q := dbq.New(s.db.Pool())
	var agents []dbq.Agent
	var err error
	if auth.RoleAtLeast(tenantRole, "admin") {
		agents, err = q.ListAgents(ctx)
	} else {
		agents, err = q.ListAgentsByUserID(ctx, pgtype.UUID{Bytes: userID, Valid: true})
	}
	if err != nil {
		s.logger.Error("list agents", zap.Error(err))
		return nil, err
	}
	out := make([]ListItem, len(agents))
	ids := make([]uuid.UUID, len(agents))
	for i, a := range agents {
		out[i] = ListItem{Agent: a}
		ids[i] = uuid.UUID(a.ID.Bytes)
	}
	if len(ids) > 0 {
		if running, err := s.containers.RunningAgents(ctx, ids); err != nil {
			s.logger.Warn("list agents: running-state lookup failed", zap.Error(err))
		} else {
			for i := range out {
				out[i].Running = running[ids[i]]
			}
		}
	}
	return out, nil
}

// Get returns the agent detail bundle: agent + connections + webhooks
// + crons + routes + running flag. Any agent member can read.
func (s *Service) Get(ctx context.Context, userID, agentID uuid.UUID) (Detail, error) {
	q := dbq.New(s.db.Pool())
	pgID := pgtype.UUID{Bytes: agentID, Valid: true}
	agent, err := q.GetAgentByID(ctx, pgID)
	if err != nil {
		return Detail{}, service.ErrNotFound
	}
	if err := s.requireAccess(ctx, q, userID, agentID); err != nil {
		return Detail{}, err
	}
	conns, _ := q.ListConnectionsByAgent(ctx, pgID)
	webhooks, _ := q.ListWebhooksByAgentWithStatus(ctx, pgID)
	crons, _ := q.ListCronsByAgent(ctx, pgID)
	routes, _ := q.ListRoutesByAgent(ctx, pgID)
	d := Detail{Agent: agent, Connections: conns, Webhooks: webhooks, Crons: crons, Routes: routes}
	if c, gerr := s.containers.GetRunning(ctx, agentID); gerr == nil && c != nil {
		d.Running = true
	}
	return d, nil
}

// Update applies a partial update; each nil field on the request keeps
// the existing value. Name/slug changes trigger an async sibling
// refresh fan-out.
func (s *Service) Update(ctx context.Context, userID, agentID uuid.UUID, req UpdateRequest) (dbq.Agent, error) {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return dbq.Agent{}, service.ErrNotFound
	}
	if err := s.requireAccess(ctx, q, userID, agentID); err != nil {
		return dbq.Agent{}, err
	}
	autoFix := agent.AutoFix
	if req.AutoFix != nil {
		autoFix = *req.AutoFix
	}
	name := agent.Name
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
		if name == "" {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "name cannot be empty")
		}
		if len(name) > 100 {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "name too long (max 100)")
		}
	}
	slug := agent.Slug
	if req.Slug != nil && *req.Slug != agent.Slug {
		slug = *req.Slug
		if !validAgentSlug(slug) {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "slug must be 2–63 chars, lowercase letters/digits separated by single dashes")
		}
	}
	nameChanged := name != agent.Name
	slugChanged := slug != agent.Slug
	updated, err := q.UpdateAgentFields(ctx, dbq.UpdateAgentFieldsParams{
		ID:      pgtype.UUID{Bytes: agentID, Valid: true},
		Name:    name,
		Slug:    slug,
		AutoFix: autoFix,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return dbq.Agent{}, service.Detail(service.ErrConflict, "agent slug already exists")
		}
		s.logger.Error("update agent", zap.Error(err))
		return dbq.Agent{}, err
	}
	if nameChanged || slugChanged {
		go s.broadcastSiblingChange(context.Background(), agentID)
	}
	return updated, nil
}

// Delete cancels in-flight builds, stops bridge pollers, stops the
// container, removes the image, drops the per-agent schema/role,
// removes the local repo, deletes the row (CASCADE handles the rest),
// and broadcasts the sibling change.
func (s *Service) Delete(ctx context.Context, userID, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := s.requireAccess(ctx, q, userID, agentID); err != nil {
		return err
	}
	s.builder.CancelBuildAndWait(agentID.String(), 30*time.Second)
	if bridgeIDs, err := q.ListBridgesByAgentID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err == nil {
		for _, bid := range bridgeIDs {
			bridgeUUID, err := uuid.FromBytes(bid.Bytes[:])
			if err != nil {
				continue
			}
			s.bridgeMgr.RemoveBridge(bridgeUUID)
		}
	}
	containerName := "airlock-agent-" + agentID.String()[:8]
	_ = s.containers.StopAgent(ctx, containerName)
	if agent.ImageRef != "" {
		_ = s.containers.RemoveImage(ctx, agent.ImageRef)
	}
	schemaName := "agent_" + strings.ReplaceAll(agentID.String(), "-", "")
	if conn, err := s.db.Pool().Acquire(ctx); err == nil {
		conn.Exec(ctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schemaName))
		conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", schemaName))
		conn.Release()
	}
	if err := builder.RemoveAgentRepo(s.builder.ReposPath(), agentID.String()); err != nil {
		s.logger.Warn("remove agent repo", zap.Error(err))
	}
	if err := q.DeleteAgent(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		s.logger.Error("delete agent", zap.Error(err))
		return err
	}
	go s.broadcastSiblingChange(context.Background(), agentID)
	return nil
}

// Stop kills the container and flips status to stopped (no auto-resume).
func (s *Service) Stop(ctx context.Context, userID, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return service.ErrNotFound
	}
	if err := s.requireAccess(ctx, q, userID, agentID); err != nil {
		return err
	}
	containerName := "airlock-agent-" + agentID.String()[:8]
	if err := s.containers.StopAgent(ctx, containerName); err != nil {
		s.logger.Error("stop agent", zap.Error(err))
		return err
	}
	_ = q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{
		ID:     pgtype.UUID{Bytes: agentID, Valid: true},
		Status: "stopped",
	})
	return nil
}

// Start resumes a stopped agent and ensures its container is up.
// Requires an existing image.
func (s *Service) Start(ctx context.Context, userID, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := s.requireAccess(ctx, q, userID, agentID); err != nil {
		return err
	}
	if agent.ImageRef == "" {
		return service.Detail(service.ErrInvalidInput, "agent has no image — build it first")
	}
	if agent.Status == "stopped" {
		if err := q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{
			ID:     pgtype.UUID{Bytes: agentID, Valid: true},
			Status: "active",
		}); err != nil {
			s.logger.Error("flip status to active", zap.Error(err))
			return err
		}
	}
	if _, err := s.dispatcher.EnsureRunning(ctx, agentID); err != nil {
		s.logger.Error("start agent", zap.Error(err))
		return err
	}
	return nil
}

// Suspend kills the container but leaves status=active for auto-resume.
func (s *Service) Suspend(ctx context.Context, userID, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return service.ErrNotFound
	}
	if err := s.requireAccess(ctx, q, userID, agentID); err != nil {
		return err
	}
	containerName := "airlock-agent-" + agentID.String()[:8]
	if err := s.containers.StopAgent(ctx, containerName); err != nil {
		s.logger.Error("suspend agent", zap.Error(err))
		return err
	}
	return nil
}

// CancelBuild is a thin wrapper around builder.CancelBuild — no
// per-agent gate today; preserved.
func (s *Service) CancelBuild(agentID uuid.UUID) error {
	if !s.builder.CancelBuild(agentID.String()) {
		return service.Detail(service.ErrConflict, "no build in progress")
	}
	return nil
}

// UpgradeRequest is the input to Upgrade. RunID is optional; if set we
// load full error context from that run so the upgrade goes via the
// auto-fix path.
type UpgradeRequest struct {
	RunID       string
	Description string
}

// Upgrade kicks off the upgrade pipeline. Admin-gated. Async — returns
// once the upgrade goroutine is queued; the runtime tracks state via
// agent_builds + WebSocket events.
func (s *Service) Upgrade(ctx context.Context, userID, agentID uuid.UUID, req UpgradeRequest) error {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := s.requireAdmin(ctx, q, userID, agentID); err != nil {
		return err
	}
	if agent.ImageRef == "" {
		go func() {
			_ = s.builder.Build(context.Background(), builder.BuildInput{
				AgentID:         agentID.String(),
				Name:            agent.Name,
				Slug:            agent.Slug,
				UserID:          uuid.UUID(agent.UserID.Bytes).String(),
				BuildProviderID: agent.BuildProviderID,
				BuildModel:      agent.BuildModel,
			})
		}()
		return nil
	}
	go func() {
		runID := req.RunID
		if runID == "" {
			runID = uuid.New().String()
		}
		input := builder.UpgradeInput{
			AgentID:     agentID.String(),
			RunID:       runID,
			Reason:      "manual",
			Description: req.Description,
		}
		if req.RunID != "" {
			if runUUID, perr := uuid.Parse(req.RunID); perr != nil {
				s.logger.Warn("upgrade: invalid run_id; proceeding as manual upgrade without diagnostics",
					zap.String("agent", agentID.String()), zap.String("run_id", req.RunID), zap.Error(perr))
			} else {
				pgRunID := pgtype.UUID{Bytes: runUUID, Valid: true}
				failedRun, gerr := q.GetRunByID(context.Background(), pgRunID)
				if gerr != nil {
					s.logger.Warn("upgrade: run not found; proceeding as manual upgrade without diagnostics",
						zap.String("agent", agentID.String()), zap.String("run_id", req.RunID), zap.Error(gerr))
				} else {
					input.Reason = "auto_fix"
					input.ErrorMessage = failedRun.ErrorMessage
					input.PanicTrace = failedRun.PanicTrace
					input.InputPayload = string(failedRun.InputPayload)
					input.Actions = string(failedRun.Actions)
					input.Logs = failedRun.StdoutLog
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
		if err := s.builder.AcquireUpgradeLock(context.Background(), agentID.String()); err != nil {
			if !errors.Is(err, builder.ErrUpgradeInProgress) {
				s.logger.Error("upgrade lock failed", zap.String("agent", agentID.String()), zap.Error(err))
			}
			return
		}
		s.builder.RunUpgrade(context.Background(), input)
	}()
	return nil
}

// RollbackRequest is the input to Rollback.
type RollbackRequest struct {
	BuildID        string
	ConversationID string
}

// Rollback reverses the agent to a previous completed build's source_ref.
// Same admin gate and async 202 shape as Upgrade.
func (s *Service) Rollback(ctx context.Context, userID, agentID uuid.UUID, req RollbackRequest) error {
	if req.BuildID == "" {
		return service.Detail(service.ErrInvalidInput, "build_id is required")
	}
	buildID, err := uuid.Parse(req.BuildID)
	if err != nil {
		return service.Detail(service.ErrInvalidInput, "invalid build_id")
	}
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := s.requireAdmin(ctx, q, userID, agentID); err != nil {
		return err
	}
	if agent.ImageRef == "" {
		return service.Detail(service.ErrConflict, "agent has no current build to roll back from")
	}
	target, err := q.GetAgentBuild(ctx, pgtype.UUID{Bytes: buildID, Valid: true})
	if err != nil {
		return service.Detail(service.ErrNotFound, "target build not found")
	}
	if uuid.UUID(target.AgentID.Bytes) != agentID {
		return service.Detail(service.ErrInvalidInput, "target build does not belong to this agent")
	}
	if target.Status != "complete" {
		return service.Detail(service.ErrConflict, "can only roll back to a completed build")
	}
	if target.SourceRef == "" {
		return service.Detail(service.ErrConflict, "target build has no source_ref")
	}
	if target.SourceRef == agent.SourceRef {
		return service.Detail(service.ErrConflict, "target build is the current build")
	}
	go func() {
		if err := s.builder.AcquireUpgradeLock(context.Background(), agentID.String()); err != nil {
			if !errors.Is(err, builder.ErrUpgradeInProgress) {
				s.logger.Error("rollback lock failed", zap.String("agent", agentID.String()), zap.Error(err))
			}
			return
		}
		s.builder.Rollback(context.Background(), builder.RollbackInput{
			AgentID:        agentID.String(),
			BuildID:        buildID.String(),
			ConversationID: req.ConversationID,
		})
	}()
	return nil
}

// ListWebhooks returns webhook rows with last-received status. No per-agent gate today.
func (s *Service) ListWebhooks(ctx context.Context, agentID uuid.UUID) ([]dbq.ListWebhooksByAgentWithStatusRow, error) {
	q := dbq.New(s.db.Pool())
	rows, err := q.ListWebhooksByAgentWithStatus(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list webhooks", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// ListCrons returns the agent's cron rows.
func (s *Service) ListCrons(ctx context.Context, agentID uuid.UUID) ([]dbq.AgentCron, error) {
	q := dbq.New(s.db.Pool())
	rows, err := q.ListCronsByAgent(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list crons", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// ListTools returns the agent's registered tool catalog.
func (s *Service) ListTools(ctx context.Context, agentID uuid.UUID) ([]dbq.AgentTool, error) {
	q := dbq.New(s.db.Pool())
	rows, err := q.ListAgentTools(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list tools", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// FireCron triggers a cron run synchronously and returns the run ID
// after draining the response body.
func (s *Service) FireCron(ctx context.Context, agentID uuid.UUID, name string) (FireCronResult, error) {
	q := dbq.New(s.db.Pool())
	cron, err := q.GetCronByAgentAndName(ctx, dbq.GetCronByAgentAndNameParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
		Name:    name,
	})
	if err != nil {
		return FireCronResult{}, service.ErrNotFound
	}
	timeout := time.Duration(cron.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	rc, runID, err := s.dispatcher.ForwardCron(ctx, agentID, name, timeout)
	if err != nil {
		s.logger.Error("fire cron", zap.Error(err))
		return FireCronResult{}, err
	}
	io.Copy(io.Discard, rc)
	rc.Close()
	return FireCronResult{RunID: runID}, nil
}

// ListBuilds returns the agent's build history (latest 50).
func (s *Service) ListBuilds(ctx context.Context, agentID uuid.UUID) ([]dbq.ListAgentBuildsByAgentRow, error) {
	q := dbq.New(s.db.Pool())
	rows, err := q.ListAgentBuildsByAgent(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list builds", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// GetBuild fetches one agent_build row plus the rollback-target row
// (for source_ref denormalization) if the build is a rollback. The
// second value is nil when the build isn't a rollback or the target row
// can't be loaded.
type BuildWithTarget struct {
	Build  dbq.AgentBuild
	Target *dbq.AgentBuild
}

func (s *Service) GetBuild(ctx context.Context, buildID uuid.UUID) (BuildWithTarget, error) {
	q := dbq.New(s.db.Pool())
	b, err := q.GetAgentBuild(ctx, pgtype.UUID{Bytes: buildID, Valid: true})
	if err != nil {
		return BuildWithTarget{}, service.ErrNotFound
	}
	out := BuildWithTarget{Build: b}
	if b.RollbackTargetID.Valid {
		if target, err := q.GetAgentBuild(ctx, b.RollbackTargetID); err == nil {
			out.Target = &target
		}
	}
	return out, nil
}

// --- git binding (per-agent external git remote) ---

// ConnectGit binds an external HTTPS git remote to the agent. Stores
// the URL, credential FK, default branch, and a freshly-generated
// HMAC secret for the webhook ingress.
func (s *Service) ConnectGit(ctx context.Context, userID, agentID uuid.UUID, req ConnectGitRequest) (GitConfig, error) {
	remote := strings.TrimSpace(req.RemoteURL)
	if remote == "" {
		return GitConfig{}, service.Detail(service.ErrInvalidInput, "git_remote_url is required")
	}
	u, perr := url.Parse(remote)
	if perr != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return GitConfig{}, service.Detail(service.ErrInvalidInput, "git_remote_url must be an http(s) URL")
	}
	credIDStr := strings.TrimSpace(req.CredentialID)
	if credIDStr == "" {
		return GitConfig{}, service.Detail(service.ErrInvalidInput, "git_credential_id is required")
	}
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		return GitConfig{}, service.Detail(service.ErrInvalidInput, "invalid git_credential_id")
	}
	branch := strings.TrimSpace(req.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return GitConfig{}, service.ErrNotFound
	}
	if err := s.requireAccess(ctx, q, userID, agentID); err != nil {
		return GitConfig{}, err
	}
	cred, err := q.GetGitCredential(ctx, pgtype.UUID{Bytes: credID, Valid: true})
	if err != nil {
		return GitConfig{}, service.Detail(service.ErrNotFound, "credential not found")
	}
	if uuid.UUID(cred.UserID.Bytes) != userID {
		return GitConfig{}, service.Detail(service.ErrForbidden, "credential does not belong to you")
	}
	secret, err := randomHex(32)
	if err != nil {
		s.logger.Error("generate webhook secret", zap.Error(err))
		return GitConfig{}, err
	}
	if err := q.ConnectAgentGit(ctx, dbq.ConnectAgentGitParams{
		ID:               pgtype.UUID{Bytes: agentID, Valid: true},
		GitRemoteUrl:     remote,
		GitCredentialID:  pgtype.UUID{Bytes: credID, Valid: true},
		GitDefaultBranch: branch,
		GitWebhookSecret: secret,
	}); err != nil {
		s.logger.Error("connect agent git", zap.Error(err))
		return GitConfig{}, err
	}
	return GitConfig{
		RemoteURL:      remote,
		CredentialID:   credID.String(),
		CredentialName: cred.Name,
		DefaultBranch:  branch,
		WebhookSecret:  secret,
	}, nil
}

// DisconnectGit resets the agent to internal-only mode. Local repo + image untouched.
func (s *Service) DisconnectGit(ctx context.Context, userID, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return service.ErrNotFound
	}
	if err := s.requireAccess(ctx, q, userID, agentID); err != nil {
		return err
	}
	if err := q.DisconnectAgentGit(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		s.logger.Error("disconnect agent git", zap.Error(err))
		return err
	}
	return nil
}

// GetGitConfig returns the current git binding (zero-valued fields when
// not connected). Agent member gate.
func (s *Service) GetGitConfig(ctx context.Context, userID, agentID uuid.UUID) (GitConfig, error) {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return GitConfig{}, service.ErrNotFound
	}
	if err := s.requireAccess(ctx, q, userID, agentID); err != nil {
		return GitConfig{}, err
	}
	cfg, err := q.GetAgentGitConfig(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("get agent git config", zap.Error(err))
		return GitConfig{}, err
	}
	out := GitConfig{
		RemoteURL:     cfg.GitRemoteUrl,
		DefaultBranch: cfg.GitDefaultBranch,
		WebhookSecret: cfg.GitWebhookSecret,
		LastSyncedRef: cfg.GitLastSyncedRef,
	}
	if cfg.GitCredentialID.Valid {
		out.CredentialID = uuid.UUID(cfg.GitCredentialID.Bytes).String()
		out.CredentialName = cfg.CredentialName.String
	}
	return out, nil
}
