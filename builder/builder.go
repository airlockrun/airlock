package builder

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// EventPublisher publishes build/upgrade lifecycle events.
// Implemented by realtime.PubSub via an adapter.
type EventPublisher interface {
	PublishBuildEvent(ctx context.Context, agentID, buildID uuid.UUID, status, errMsg, phase string, tasksDone, tasksTotal int32)
	PublishBuildLogLine(ctx context.Context, agentID, buildID uuid.UUID, seq int64, stream, line string)
	PublishBuildTodos(ctx context.Context, buildID uuid.UUID, seq int64, todosJSON []byte)
}

// noopPublisher is used when no EventPublisher is configured.
type noopPublisher struct{}

func (noopPublisher) PublishBuildEvent(context.Context, uuid.UUID, uuid.UUID, string, string, string, int32, int32) {
}
func (noopPublisher) PublishBuildLogLine(context.Context, uuid.UUID, uuid.UUID, int64, string, string) {
}
func (noopPublisher) PublishBuildTodos(context.Context, uuid.UUID, int64, []byte) {}

// BuildService orchestrates the agent build and upgrade pipeline.
type BuildService struct {
	cfg                   *config.Config
	db                    *db.DB
	containers            container.ContainerManager
	encryptor             secrets.Store
	providerHTTPClient    *http.Client
	artifacts             *storage.S3Client
	events                EventPublisher
	upgradeNotifier       PostUpgradeNotifier
	upgradeSystemNotifier PostUpgradeSystemNotifier
	buildSystemNotifier   PostBuildSystemNotifier
	jobWake               func()
	logger                *zap.Logger

	mu       sync.Mutex
	inFlight map[string]*buildHandle // agentID → handle for cancel + wait

	// buildSem caps concurrent builds on this worker replica. Every pipeline
	// path acquires a slot before touching the database or source tree. It is
	// sized at NumCPU/2 by default; AIRLOCK_BUILD_PARALLELISM overrides it.
	// Per-agent PostgreSQL advisory locks provide cross-replica correctness.
	buildSem chan struct{}
}

// buildHandle tracks a running build/upgrade so callers can cancel and
// optionally block until the goroutine has fully torn down its toolserver
// and DB writes — needed by Delete to avoid racing the workspace rm and
// agent-row delete against in-flight writes.
type buildHandle struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// New creates a BuildService. Panics if any dependency is nil.
func New(cfg *config.Config, database *db.DB, containers container.ContainerManager, encryptor secrets.Store, providerHTTPClient *http.Client, artifacts *storage.S3Client, logger *zap.Logger) *BuildService {
	if cfg == nil {
		panic("builder: cfg is nil")
	}
	if database == nil {
		panic("builder: db is nil")
	}
	if containers == nil {
		panic("builder: containers is nil")
	}
	if encryptor == nil {
		panic("builder: encryptor is nil")
	}
	if providerHTTPClient == nil {
		panic("builder: provider HTTP client is nil")
	}
	if artifacts == nil {
		panic("builder: artifact storage is nil")
	}
	if logger == nil {
		panic("builder: logger is nil")
	}
	parallelism := buildParallelism()
	logger.Info("build concurrency limit", zap.Int("parallelism", parallelism))
	return &BuildService{
		cfg:                cfg,
		db:                 database,
		containers:         containers,
		encryptor:          encryptor,
		providerHTTPClient: providerHTTPClient,
		artifacts:          artifacts,
		events:             noopPublisher{},
		logger:             logger,
		inFlight:           make(map[string]*buildHandle),
		buildSem:           make(chan struct{}, parallelism),
	}
}

// ReposPath returns the base directory holding per-agent git repos.
// Each agent's source lives at <ReposPath>/<agentID>/.
func (b *BuildService) ReposPath() string {
	return b.cfg.AgentReposPath
}

// AgentRepoPath returns the on-disk path for a single agent's repo.
func (b *BuildService) AgentRepoPath(agentID string) string {
	return AgentRepoPath(b.cfg.AgentReposPath, agentID)
}

// SetEventPublisher sets the event publisher for build/upgrade lifecycle events.
func (b *BuildService) SetEventPublisher(ep EventPublisher) {
	b.events = ep
}

// SetUpgradeNotifier sets the notifier called after an upgrade
// initiated from an agent's web/bridge/A2A conversation finishes.
func (b *BuildService) SetUpgradeNotifier(n PostUpgradeNotifier) {
	b.upgradeNotifier = n
}

// SetUpgradeSystemNotifier sets the notifier called after an upgrade
// initiated from a system-agent conversation finishes. Mirrors
// SetUpgradeNotifier; the builder routes by UpgradeInput's
// SystemConversationID vs ConversationID (mutually exclusive — see
// notifyUpgradeOutcome).
func (b *BuildService) SetUpgradeSystemNotifier(n PostUpgradeSystemNotifier) {
	b.upgradeSystemNotifier = n
}

// SetBuildSystemNotifier sets the notifier called after an INITIAL build
// kicked off from a system-agent create_agent tool finishes. Routed by
// BuildInput.SystemConversationID (system-agent create path only).
func (b *BuildService) SetBuildSystemNotifier(n PostBuildSystemNotifier) {
	b.buildSystemNotifier = n
}

// SetJobWake wires the local durable-job worker after trigger startup.
func (b *BuildService) SetJobWake(wake func()) {
	if wake == nil {
		panic("builder: job wake is nil")
	}
	b.jobWake = wake
}

// notifyBuildOutcome posts an initial-build result into the originating
// system-agent conversation (when a create_agent tool triggered it). No-op
// for the web create path, which carries no conversation id and surfaces
// status via the build view.
func (b *BuildService) notifyBuildOutcome(ctx context.Context, agentID uuid.UUID, systemConversationID, status, message string) {
	if systemConversationID == "" || b.buildSystemNotifier == nil {
		return
	}
	tid, err := uuid.Parse(systemConversationID)
	if err != nil {
		b.logger.Error("invalid system conversation id on build outcome",
			zap.String("conversation_id", systemConversationID), zap.Error(err))
		return
	}
	if nerr := b.buildSystemNotifier.NotifyBuildComplete(ctx, agentID, tid, status, message); nerr != nil {
		b.logger.Error("post-build system-conversation notification failed", zap.Error(nerr))
	}
}

// startBuild registers a cancellable context for a build/upgrade.
// Returns the cancellable context. Caller must call finishBuild when done.
func (b *BuildService) startBuild(agentID string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	b.mu.Lock()
	b.inFlight[agentID] = &buildHandle{cancel: cancel, done: make(chan struct{})}
	b.mu.Unlock()
	return ctx, cancel
}

// finishBuild removes the handle for a completed build and signals any
// CancelBuildAndWait callers blocked on its done channel.
func (b *BuildService) finishBuild(agentID string) {
	b.mu.Lock()
	h, ok := b.inFlight[agentID]
	delete(b.inFlight, agentID)
	b.mu.Unlock()
	if ok {
		close(h.done)
	}
}

// makeCodegenTempDir creates a per-build scratch directory. In dev mode
// (AgentCodegenPath empty) it falls back to /tmp like the older code path,
// so `go run ./cmd/airlock` continues to work without compose. In compose
// mode it creates the dir inside AgentCodegenPath, which lives inside the
// shared named volume — this is what makes sibling-container bind mounts
// resolve correctly under docker-in-docker.
func (b *BuildService) makeCodegenTempDir(prefix string) (string, error) {
	if b.cfg.AgentCodegenPath != "" {
		if err := os.MkdirAll(b.cfg.AgentCodegenPath, 0o755); err != nil {
			return "", fmt.Errorf("mkdir codegen path: %w", err)
		}
		return os.MkdirTemp(b.cfg.AgentCodegenPath, prefix)
	}
	return os.MkdirTemp("", prefix)
}

// CancelBuild cancels a running build/upgrade for the given agent.
// Returns true if a build was running and cancelled. Does not block on
// teardown — use CancelBuildAndWait when the caller needs the toolserver
// and DB writes to settle before proceeding.
func (b *BuildService) CancelBuild(agentID string) bool {
	b.mu.Lock()
	h, ok := b.inFlight[agentID]
	b.mu.Unlock()
	if ok {
		h.cancel()
	}
	return ok
}

// CancelBuildAndWait cancels a running build/upgrade and blocks until the
// goroutine has run its deferred cleanup (toolserver SIGKILL, DB status
// write) or until timeout elapses. Returns true if a build was running.
// Used by Delete to avoid racing the workspace rm and agent-row delete
// against the upgrade's in-flight writes.
func (b *BuildService) CancelBuildAndWait(agentID string, timeout time.Duration) bool {
	b.mu.Lock()
	h, ok := b.inFlight[agentID]
	b.mu.Unlock()
	if !ok {
		return false
	}
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(timeout):
	}
	return true
}

// BuildInput describes what to build.
type BuildInput struct {
	AgentID          string
	Name             string
	Slug             string
	OwnerPrincipalID string
	InitiatorUserID  pgtype.UUID // user who triggered the build; attributes codegen spend (falls back to owner)
	BuildProviderID  pgtype.UUID // providers row FK; pairs with BuildModel
	BuildModel       string      // bare model name; "" + invalid FK ⇄ inherit system default
	Instructions     string      // optional: when non-empty, run Sol code generation after scaffold
	Message          string      // optional build description persisted without invoking Sol

	// SkipScaffold, when true, provisions the agent's DB schema but does NOT
	// re-run the scaffold (CommitScaffold/MergeBranch/CleanWorktree) that
	// overwrites scaffold-managed files. Set for a clone whose repo is copied
	// in already-complete — re-scaffolding would clobber the source agent's
	// customizations to those files (viewmodel.go, main.go, index.templ, …).
	SkipScaffold bool

	// Optional external-git connection. When GitRemoteURL is non-empty,
	// the agent is connected to the remote during Build and the first
	// push happens via Execute's post-merge push (Phase C2). The API
	// handler enforces that GitCredentialID belongs to OwnerPrincipalID before
	// calling Build.
	GitRemoteURL     string
	GitCredentialID  pgtype.UUID
	GitDefaultBranch string // defaults to "main" when empty
	GitMode          string

	// SystemConversationID, when set, is the system-agent conversation that
	// triggered this build via create_agent. On completion the build outcome
	// is posted back there + the system agent resumes. Empty for the web
	// create path (no conversation).
	SystemConversationID string
}

// Build runs the initial-build pipeline: scaffold → Sol codegen (if
// instructions present) → docker build → start container. Thin wrapper
// over Execute that handles the build-specific outer lifecycle: load
// or create the agent row, flip agents.status to building, route
// failures into agents.status=failed. Synchronous; caller runs in a
// goroutine.
func (b *BuildService) Build(_ context.Context, input BuildInput) (err error) {
	ctx, cancel := b.startBuild(input.AgentID)
	defer cancel()
	defer b.finishBuild(input.AgentID)

	b.logger.Info("build started",
		zap.String("agent_id", input.AgentID),
		zap.String("slug", input.Slug),
		zap.Bool("has_instructions", input.Instructions != ""))

	q := dbq.New(b.db.Pool())

	var agent dbq.Agent
	if input.AgentID != "" {
		agent, err = q.GetAgentByID(ctx, mustParseUUID(input.AgentID))
		if err != nil {
			return fmt.Errorf("get agent: %w", err)
		}
	} else {
		ownerUUID := mustParseUUID(input.OwnerPrincipalID)
		agent, err = q.CreateAgent(ctx, dbq.CreateAgentParams{
			Name:             input.Name,
			Slug:             input.Slug,
			OwnerPrincipalID: ownerUUID,
			Config:           []byte("{}"),
		})
		if err != nil {
			return fmt.Errorf("create agent: %w", err)
		}
		if input.BuildModel != "" {
			_ = q.UpdateAgentModels(ctx, dbq.UpdateAgentModelsParams{
				ID:              agent.ID,
				BuildProviderID: input.BuildProviderID,
				BuildModel:      input.BuildModel,
			})
			agent.BuildProviderID = input.BuildProviderID
			agent.BuildModel = input.BuildModel
		}
	}

	agent, err = q.StartInitialAgentBuild(ctx, dbq.StartInitialAgentBuildParams{
		ID:                agent.ID,
		AgentTokenVersion: agent.AgentTokenVersion,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDeploymentConflict
	}
	if err != nil {
		return fmt.Errorf("start initial build: %w", err)
	}
	reservedAgent := agent
	reservationActive := true
	defer func() {
		if err != nil && reservationActive {
			_, _ = q.FailInitialAgentBuild(context.Background(), dbq.FailInitialAgentBuildParams{
				ID: reservedAgent.ID, ErrorMessage: err.Error(), AgentTokenVersion: reservedAgent.AgentTokenVersion,
			})
		}
	}()

	// Attach the optional external git remote BEFORE Execute runs, so
	// Phase C2 (post-merge push) sees it and pushes the scaffold +
	// codegen to the remote in one shot.
	if input.GitRemoteURL != "" {
		if input.GitMode != "read_write" && input.GitMode != "read_only" {
			return fmt.Errorf("git mode must be read_write or read_only when a remote is configured")
		}
		branch := input.GitDefaultBranch
		if branch == "" {
			branch = "main"
		}
		secret, err := randomHexBytes(32)
		if err != nil {
			return fmt.Errorf("generate webhook secret: %w", err)
		}
		storedSecret, err := b.encryptor.Put(ctx, "agent/"+uuid.UUID(agent.ID.Bytes).String()+"/git_webhook_secret", secret)
		if err != nil {
			return fmt.Errorf("encrypt webhook secret: %w", err)
		}
		if err := q.ConnectAgentGit(ctx, dbq.ConnectAgentGitParams{
			ID:               agent.ID,
			GitRemoteUrl:     input.GitRemoteURL,
			GitCredentialID:  input.GitCredentialID,
			GitDefaultBranch: branch,
			GitWebhookSecret: storedSecret,
			GitMode:          input.GitMode,
		}); err != nil {
			return fmt.Errorf("connect agent git: %w", err)
		}
		// Re-read so plan.Agent below carries the connected Git fields.
		reloaded, err := q.GetAgentByID(ctx, agent.ID)
		if err != nil {
			return fmt.Errorf("reload agent after git connect: %w", err)
		}
		agent = reloaded
	}

	plan := BuildPlan{
		Agent:           agent,
		Kind:            BuildKindBuild,
		Instruction:     input.Instructions,
		Message:         input.Message,
		SkipScaffold:    input.SkipScaffold,
		Reason:          "manual",
		RunID:           uuid.New().String(),
		InitiatorUserID: input.InitiatorUserID,
		Scaffold: &ScaffoldInputs{
			Name:            input.Name,
			Slug:            input.Slug,
			BuildProviderID: input.BuildProviderID,
			BuildModel:      input.BuildModel,
		},
	}
	reservationActive = false
	summary, err := b.Execute(ctx, plan)
	if err != nil {
		errMsg := err.Error()
		if errors.Is(err, context.Canceled) {
			errMsg = "cancelled by user"
			b.logger.Info("build cancelled", zap.String("agent_id", input.AgentID))
		} else {
			b.logger.Error("build failed", zap.String("agent_id", input.AgentID))
		}
		failureTokenVersion := agent.AgentTokenVersion
		var attemptErr *deploymentAttemptError
		if errors.As(err, &attemptErr) {
			failureTokenVersion = attemptErr.tokenVersion
		}
		_, _ = q.FailInitialAgentBuild(context.Background(), dbq.FailInitialAgentBuildParams{
			ID:                agent.ID,
			ErrorMessage:      errMsg,
			AgentTokenVersion: failureTokenVersion,
		})
		// Cancellation already surfaced via the build view toast; don't post.
		if !errors.Is(err, context.Canceled) {
			b.notifyBuildOutcome(context.Background(), uuid.UUID(agent.ID.Bytes), input.SystemConversationID, "error", errMsg)
		}
		return err
	}
	b.logger.Info("build completed", zap.String("agent_id", input.AgentID))
	msg := summary // the agent-builder's exit summary when codegen ran
	if msg == "" {
		msg = fmt.Sprintf("Agent %q is built and active.", agent.Name)
	}
	b.notifyBuildOutcome(context.Background(), uuid.UUID(agent.ID.Bytes), input.SystemConversationID, "success", msg)
	return nil
}

// buildCodegenPrompt is the user-turn message for a fresh build. The
// scaffold is empty, so this is a from-scratch implementation request —
// not a spec the model should reconcile a tree against. The agentsdk
// reference lives at /libs/agentsdk/REFERENCE.md and is pulled in by the
// system prompt's First Step; this message is just the task.
func buildCodegenPrompt(agent dbq.Agent, instructions string) string {
	return fmt.Sprintf(`Build a new agent from scratch in the scaffolded workspace.

Agent: %s (slug: %s, id: %s)

What it should do:

%s`, agent.Name, agent.Slug, uuidString(agent.ID), instructions)
}

// buildUpgradePrompt is the user-turn message for a codegen upgrade.
// Rebuilds never reach here (doUpgrade branches earlier). The framing keys
// off whether the requester supplied a change description:
//   - no description + diagnostics → a pure failure-fix (auto-fix of a
//     crashing/failing agent): diagnose and repair, minimal change.
//   - a description → a change request: implement it. When diagnostics are
//     also present (e.g. the prior build broke), fix that breakage as part
//     of delivering the change rather than abandoning the request.
//
// Both frame the work as incremental against an already-working tree so the
// model preserves everything unrelated. The internal Reason enum is
// deliberately NOT surfaced — it means nothing to the model.
func buildUpgradePrompt(agent dbq.Agent, input UpgradeInput, hasDiagnostics bool) string {
	name := fmt.Sprintf("%s (slug: %s, id: %s)", agent.Name, agent.Slug, uuidString(agent.ID))
	desc := strings.TrimSpace(input.Description)

	if desc == "" {
		if hasDiagnostics {
			return fmt.Sprintf(`The EXISTING agent %s is failing. Diagnose and fix the failure described in DIAGNOSTICS.md in the workspace. Make the minimal change that fixes it and preserve everything not involved in the fix — do not remove tools, connections, routes, or files unrelated to the failure.`, name)
		}
		// Degenerate: an auto_fix whose run carried no error context and
		// no description. Don't invent work — just keep it building.
		desc = "(no description provided — make no behavioral changes; only ensure the agent still builds.)"
	}

	p := fmt.Sprintf(`You are upgrading the EXISTING agent %s. Its workspace already contains a working codebase. This is an incremental change request — implement it and preserve everything not related to it. Do not remove tools, connections, routes, or files the request doesn't mention.

Requested change:

%s`, name, desc)
	if hasDiagnostics {
		p += "\n\nThe workspace code may currently be in a failing state — DIAGNOSTICS.md describes the most recent failure (build or runtime). Fix it as part of this change so the agent builds and runs."
	}
	return p
}

// writeUpgradeDiagnostics writes DIAGNOSTICS.md only when the upgrade
// carries failure context (auto_fix path). Returns true when a file was
// written. Pure "manual"/"llm_request" upgrades carry no error context
// and get no file — the request message alone is the brief.
func writeUpgradeDiagnostics(dir string, input UpgradeInput) (bool, error) {
	var content string
	if input.ErrorMessage != "" {
		content += fmt.Sprintf("## Error Message\n\n```\n%s\n```\n", input.ErrorMessage)
	}
	if input.PanicTrace != "" {
		content += fmt.Sprintf("\n## Panic Trace\n\n```\n%s\n```\n", input.PanicTrace)
	}
	if input.InputPayload != "" {
		content += fmt.Sprintf("\n## Failed Input\n\n```json\n%s\n```\n", input.InputPayload)
	}
	if input.Actions != "" {
		content += fmt.Sprintf("\n## Recorded Actions\n\n```json\n%s\n```\n", input.Actions)
	}
	if input.Messages != "" {
		content += fmt.Sprintf("\n## Conversation Messages\n\n```\n%s\n```\n", input.Messages)
	}
	if input.Logs != "" {
		content += fmt.Sprintf("\n## Run Logs\n\n```\n%s\n```\n", input.Logs)
	}
	if input.BuildError != "" {
		content += fmt.Sprintf("\n## Previous Build Failure\n\nThe most recent build of this agent failed. Its committed code is in the workspace; fix the cause so the build succeeds.\n\n```\n%s\n```\n", input.BuildError)
	}
	if input.BuildLog != "" {
		content += fmt.Sprintf("\n## Previous Build Log (tail)\n\n```\n%s\n```\n", input.BuildLog)
	}
	if content == "" {
		return false, nil
	}
	runRef := "the failed run"
	if input.RunID != "" {
		runRef = "run " + input.RunID
	}
	header := fmt.Sprintf("# Failure diagnostics (%s)\n\nContext from the run that triggered this upgrade.\n\n", runRef)
	return true, os.WriteFile(filepath.Join(dir, "DIAGNOSTICS.md"), []byte(header+content), 0o644)
}

// ensureAgentRole reconciles the agent's Postgres role + schema to the given
// password — but only when needed. If the role already authenticates with this
// password it does nothing: re-running ALTER ROLE ... PASSWORD rewrites the
// scram-sha-256 verifier (new salt), and an ALTER that lands during the agent's
// in-flight auth handshake fails it with 28P01 for the *correct* password.
// Repeated reconciles (build + cold starts) churn the verifier and break health
// checks. So we provision only on a genuine auth failure: drift or a missing
// role. create_agent_role is idempotent (CREATE if missing, ALTER otherwise).
func (b *BuildService) ensureAgentRole(ctx context.Context, schemaName, password string) error {
	if b.roleAuthenticates(ctx, schemaName, password) {
		return nil // already correct — don't churn the SCRAM verifier
	}

	conn, err := b.db.Pool().Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	// SECURITY DEFINER bridge — avoids granting CREATEROLE to airlock_app.
	if _, err := conn.Exec(ctx, "SELECT create_agent_role($1, $2)", schemaName, password); err != nil {
		return fmt.Errorf("create role: %w", err)
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s AUTHORIZATION %s", schemaName, schemaName)); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

// roleAuthenticates reports whether the agent role can connect with password.
// Used to skip a gratuitous ALTER ROLE (see ensureAgentRole) when the role is
// already correct — false on a missing role or a wrong password.
func (b *BuildService) roleAuthenticates(ctx context.Context, roleName, password string) bool {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, b.agentDBURLBase(b.cfg.DBHost, b.cfg.DBPort, roleName, password))
	if err != nil {
		return false
	}
	_ = conn.Close(context.Background())
	return true
}

// newDBPassword returns a fresh 32-byte hex-encoded password for a new agent
// role. Minted only on first creation; rebuilds reuse the stored value so the
// role password is never rotated out from under a running container.
func newDBPassword() (string, error) {
	pwBytes := make([]byte, 32)
	if _, err := rand.Read(pwBytes); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return hex.EncodeToString(pwBytes), nil
}

// agentDBURL builds a Postgres connection URL for an agent's dedicated role.
// Uses DBHostAgent (Docker network hostname) — for agent containers.
//
// search_path is set to "{schema},public": agents create their own tables
// in the per-agent schema (first entry wins for unqualified DDL), but type
// lookups and built-ins resolve through public — that's where shared
// extensions like pgvector live (CREATE EXTENSION is per-database, not
// per-schema, and lands in the schema current at install time, by default
// public). Without `public` on the search path, an agent migration that
// references the `vector` type errors "type vector does not exist".
func (b *BuildService) agentDBURL(roleName, password, schemaName string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?search_path=%s&sslmode=%s",
		roleName, url.QueryEscape(password), b.cfg.DBHostAgent, b.cfg.DBPortAgent,
		b.cfg.DBName, schemaName+",public", b.cfg.DBSSLMode)
}

// agentDBURLLocal builds a Postgres connection URL using DBHost.
// Used for build-time migration validation which runs in the Airlock process.
func (b *BuildService) agentDBURLLocal(roleName, password, schemaName string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?search_path=%s&sslmode=%s",
		roleName, url.QueryEscape(password), b.cfg.DBHost, b.cfg.DBPort,
		b.cfg.DBName, schemaName+",public", b.cfg.DBSSLMode)
}

// agentDBURLBase builds a Postgres connection URL without search_path.
// Used for psql which doesn't support search_path as a URI parameter.
func (b *BuildService) agentDBURLBase(host, port, roleName, password string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		roleName, url.QueryEscape(password), host, port,
		b.cfg.DBName, b.cfg.DBSSLMode)
}

// runDownToCheck runs the given agent image with AGENT_MIGRATE_DOWN_TO
// pointing at version targetVersion, against dbURL. Used by rollback's
// Phase E pre-flight (on a clone) and Phase E2 apply (on the live
// schema). The image is the CURRENT pre-rollback image — it knows
// about the migrations being reversed; the target's image does not.
//
// Exits 0 on success, non-zero with stderr captured on failure. Same
// container envelope as validateMigrations so failures surface the
// same way and the orchestrator sees a one-shot completion.
func (b *BuildService) runDownToCheck(ctx context.Context, imageTag, dbURL string, targetVersion int, logLine func(string)) error {
	if imageTag == "" {
		return errors.New("no current image to run down-migrations from")
	}
	logLine(fmt.Sprintf("Migrating down to version %d using image %s...", targetVersion, imageTag))

	args := []string{
		"run", "--rm",
		"-e", fmt.Sprintf("AGENT_MIGRATE_DOWN_TO=%d", targetVersion),
		"-e", "AIRLOCK_DB_URL",
		"-e", "AIRLOCK_AGENT_ID=rollback",
		"-e", "AIRLOCK_API_URL=http://invalid-not-used-in-down-mode",
		"-e", "AIRLOCK_AGENT_TOKEN=rollback",
	}
	if b.cfg.DockerNetwork != "" {
		args = append(args, "--network", b.cfg.DockerNetwork)
	}
	args = append(args, imageTag)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(), "AIRLOCK_DB_URL="+dbURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("down-to %d failed: %w\n%s", targetVersion, err, string(out))
	}
	return nil
}

// runMigrateUp restores the live schema with the current image when a rollback
// cutover cannot complete after applying down-migrations.
func (b *BuildService) runMigrateUp(ctx context.Context, imageTag, dbURL string, logLine func(string)) error {
	if imageTag == "" {
		return errors.New("no current image to run up-migrations from")
	}
	logLine("Restoring current database migrations...")
	args := []string{
		"run", "--rm",
		"-e", "AGENT_MIGRATE_UP_ONLY=1",
		"-e", "AIRLOCK_DB_URL",
		"-e", "AIRLOCK_AGENT_ID=rollback-recovery",
		"-e", "AIRLOCK_API_URL=http://invalid-not-used-in-up-mode",
		"-e", "AIRLOCK_AGENT_TOKEN=rollback-recovery",
	}
	if b.cfg.DockerNetwork != "" {
		args = append(args, "--network", b.cfg.DockerNetwork)
	}
	args = append(args, imageTag)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(), "AIRLOCK_DB_URL="+dbURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("migration restore failed: %w\n%s", err, string(out))
	}
	return nil
}

// validateMigrations runs the agent image with AGENT_VALIDATE_MIGRATIONS=1
// against the provided test DB. The agent runs goose up → down → up to verify
// that migrations (both SQL and Go, interleaved) are reversible and don't
// break each other, then exits.
//
// Go migrations that touch external services (S3, Airlock API, connection
// credentials) should guard with `if os.Getenv("AGENT_VALIDATE_MIGRATIONS") == "1"`
// since those services are not available during validation.
func (b *BuildService) validateMigrations(ctx context.Context, imageTag, dbURL string, logLine func(string)) error {
	logLine("Validating migrations (up → down → up)...")

	args := []string{
		"run", "--rm",
		"-e", "AGENT_VALIDATE_MIGRATIONS=1",
		"-e", "AIRLOCK_DB_URL",
		"-e", "AIRLOCK_AGENT_ID=validate",
		"-e", "AIRLOCK_API_URL=http://invalid-not-used-in-validate-mode",
		"-e", "AIRLOCK_AGENT_TOKEN=validate",
	}
	if b.cfg.DockerNetwork != "" {
		args = append(args, "--network", b.cfg.DockerNetwork)
	}
	args = append(args, imageTag)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(), "AIRLOCK_DB_URL="+dbURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("migration validation failed: %w\n%s", err, string(out))
	}
	logLine("Migrations validated successfully")
	return nil
}

// dropSchemaClone drops a cloned schema.
func (b *BuildService) dropSchemaClone(ctx context.Context, cloneName string) error {
	conn, err := b.db.Pool().Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", cloneName))
	return err
}

// RecoverStuckOperations recovers builds whose source lock is not held by a
// live replica. Active builds are skipped without waiting.
func (b *BuildService) RecoverStuckOperations(ctx context.Context) error {
	q := dbq.New(b.db.Pool())
	builds, err := q.ListBuildingAgentBuilds(ctx)
	if err != nil {
		return fmt.Errorf("list building agent builds: %w", err)
	}
	for _, listed := range builds {
		agentID := uuidString(listed.AgentID)
		lock, acquired, err := b.TryAcquireSourceLock(ctx, agentID)
		if err != nil {
			return fmt.Errorf("try recovery lock for agent %s: %w", agentID, err)
		}
		if !acquired {
			continue
		}
		recoverErr := b.recoverAgentBuild(ctx, listed.AgentID, listed.ID)
		lock.Unlock()
		if recoverErr != nil {
			return fmt.Errorf("recover build %s for agent %s: %w", uuidString(listed.ID), agentID, recoverErr)
		}
	}
	return nil
}

func (b *BuildService) recoverAgentBuild(ctx context.Context, agentID, buildID pgtype.UUID) error {
	q := dbq.New(b.db.Pool())
	build, err := q.GetAgentBuild(ctx, buildID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("reload build: %w", err)
	}
	if build.Status != "building" {
		return nil
	}
	cloneName := schemaCloneName("agent_"+sanitizeUUID(uuidString(agentID)), uuid.UUID(build.ID.Bytes))
	if err := b.dropSchemaCloneWithTimeout(cloneName); err != nil {
		return fmt.Errorf("drop interrupted build schema clone: %w", err)
	}
	if build.DeploymentPhase == "complete" {
		if _, err := q.CompleteRecoveredAgentBuild(ctx, dbq.CompleteRecoveredAgentBuildParams{BuildID: buildID, AgentID: agentID}); err != nil {
			return fmt.Errorf("complete deployed build: %w", err)
		}
		return nil
	}

	agent, err := q.GetAgentByID(ctx, agentID)
	if err != nil {
		return fmt.Errorf("reload agent: %w", err)
	}
	if !agent.JobDispatchPausedBuildID.Valid && build.DeploymentPhase == "starting" && agent.Status == "stopped" {
		runtimeLock, err := b.db.AcquireAdvisoryLock(ctx, "agent-runtime:"+uuidString(agent.ID))
		if err != nil {
			return fmt.Errorf("lock stopped agent runtime for recovery: %w", err)
		}
		defer runtimeLock.Unlock()
		if build.Type == string(BuildKindRollback) {
			password, err := b.encryptor.Get(ctx, "agent/"+uuidString(agent.ID)+"/db_password", agent.DbPassword)
			if err != nil {
				return fmt.Errorf("decrypt stopped rollback database password: %w", err)
			}
			schema := "agent_" + sanitizeUUID(uuidString(agent.ID))
			logLine := func(line string) {
				b.logger.Info("recover stopped rollback", zap.String("agent", uuidString(agent.ID)), zap.String("message", line))
			}
			if err := b.runMigrateUp(ctx, agent.ImageRef, b.agentDBURL(schema, password, schema), logLine); err != nil {
				return fmt.Errorf("restore stopped rollback migrations: %w", err)
			}
		}
		rows, err := q.UpdateAgentBuildDeploymentPhase(ctx, dbq.UpdateAgentBuildDeploymentPhaseParams{
			DeploymentPhase: "failed", BuildID: build.ID, AgentID: agent.ID, DeploymentToken: build.DeploymentToken,
		})
		if err != nil || rows != 1 {
			if err == nil {
				err = ErrDeploymentConflict
			}
			return fmt.Errorf("fail recovered stopped deployment: %w", err)
		}
	}
	if agent.JobDispatchPausedBuildID.Valid && agent.JobDispatchPausedBuildID.Bytes == build.ID.Bytes {
		switch build.DeploymentPhase {
		case "paused", "starting", "rollback":
			if agent.Status == "building" && agent.ImageRef != "" && build.Type != string(BuildKindBuild) {
				agent.Status = "failed"
			}
			password, err := b.encryptor.Get(ctx, "agent/"+uuidString(agent.ID)+"/db_password", agent.DbPassword)
			if err != nil {
				return fmt.Errorf("decrypt agent database password: %w", err)
			}
			schema := "agent_" + sanitizeUUID(uuidString(agent.ID))
			runtimeLock, err := b.db.AcquireAdvisoryLock(ctx, "agent-runtime:"+uuidString(agent.ID))
			if err != nil {
				return fmt.Errorf("lock agent runtime for recovery: %w", err)
			}
			if err := b.rollbackPausedDeployment(agent, build.ID, build.DeploymentToken, b.agentDBURL(schema, password, schema)); err != nil {
				runtimeLock.Unlock()
				return fmt.Errorf("roll back paused deployment: %w", err)
			}
			runtimeLock.Unlock()
		}
	}

	const message = "interrupted by Airlock restart"
	tx, err := b.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin recovery: %w", err)
	}
	defer tx.Rollback(context.Background())
	qtx := dbq.New(tx)
	if _, err := qtx.GetAgentByIDForUpdate(ctx, agentID); err != nil {
		return fmt.Errorf("lock recovered agent: %w", err)
	}
	if _, err := qtx.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{BuildID: buildID, AgentID: agentID}); err != nil {
		return fmt.Errorf("lock recovered build: %w", err)
	}
	rows, err := qtx.FailRecoveredAgentBuild(ctx, dbq.FailRecoveredAgentBuildParams{
		ErrorMessage: message, BuildID: buildID, AgentID: agentID,
	})
	if err != nil {
		return fmt.Errorf("fail interrupted build: %w", err)
	}
	if rows == 0 {
		return tx.Commit(ctx)
	}
	if _, err := qtx.FailRecoveredAgentLifecycle(ctx, dbq.FailRecoveredAgentLifecycleParams{
		ErrorMessage: message, AgentID: agentID, BuildID: buildID,
	}); err != nil {
		return fmt.Errorf("fail interrupted lifecycle: %w", err)
	}
	return tx.Commit(ctx)
}

// mustParseUUID converts a string to pgtype.UUID, panicking on failure.
func mustParseUUID(s string) pgtype.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		panic(fmt.Sprintf("invalid UUID %q: %v", s, err))
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}

// uuidString converts a pgtype.UUID to a string.
func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	id := uuid.UUID(u.Bytes)
	return id.String()
}

// sanitizeUUID removes hyphens from a UUID for use as a schema name.
func sanitizeUUID(id string) string {
	out := make([]byte, 0, len(id))
	for _, c := range id {
		if c != '-' {
			out = append(out, byte(c))
		}
	}
	return string(out)
}

// ErrUpgradeInProgress is returned when an upgrade is already running for the agent.
var ErrUpgradeInProgress = errors.New("upgrade already in progress")
