package builder

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// EventPublisher publishes build/upgrade lifecycle events.
// Implemented by realtime.PubSub via an adapter.
type EventPublisher interface {
	PublishBuildEvent(ctx context.Context, agentID, buildID uuid.UUID, status, errMsg string)
	PublishBuildLogLine(ctx context.Context, agentID, buildID uuid.UUID, seq int64, stream, line string)
}

// noopPublisher is used when no EventPublisher is configured.
type noopPublisher struct{}

func (noopPublisher) PublishBuildEvent(context.Context, uuid.UUID, uuid.UUID, string, string) {}
func (noopPublisher) PublishBuildLogLine(context.Context, uuid.UUID, uuid.UUID, int64, string, string) {
}

// BuildService orchestrates the agent build and upgrade pipeline.
type BuildService struct {
	cfg             *config.Config
	db              *db.DB
	containers      container.ContainerManager
	encryptor       secrets.Store
	events          EventPublisher
	upgradeNotifier PostUpgradeNotifier
	logger          *zap.Logger

	mu       sync.Mutex
	inFlight map[string]*buildHandle // agentID → handle for cancel + wait

	// buildSem caps concurrent in-flight builds across the whole
	// service. Every pipeline path — initial build, manual upgrade,
	// rollback, mass-rebuild — acquires one slot inside Execute. Sized
	// at NumCPU/2 by default (Go compilation is RAM-hungry; running
	// every core in parallel reliably OOMs small VPSes); operator
	// override via AIRLOCK_BUILD_PARALLELISM. Sized once at New() so
	// the limit can't drift mid-run.
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
func New(cfg *config.Config, database *db.DB, containers container.ContainerManager, encryptor secrets.Store, logger *zap.Logger) *BuildService {
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
	if logger == nil {
		panic("builder: logger is nil")
	}
	parallelism := buildParallelism()
	logger.Info("build concurrency limit", zap.Int("parallelism", parallelism))
	return &BuildService{
		cfg:        cfg,
		db:         database,
		containers: containers,
		encryptor:  encryptor,
		events:     noopPublisher{},
		logger:     logger,
		inFlight:   make(map[string]*buildHandle),
		buildSem:   make(chan struct{}, parallelism),
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

// SetUpgradeNotifier sets the notifier called after successful upgrades
// to notify the originating conversation.
func (b *BuildService) SetUpgradeNotifier(n PostUpgradeNotifier) {
	b.upgradeNotifier = n
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
	AgentID         string
	Name            string
	Slug            string
	UserID          string
	BuildProviderID pgtype.UUID // providers row FK; pairs with BuildModel
	BuildModel      string      // bare model name; "" + invalid FK ⇄ inherit system default
	Instructions    string      // optional: when non-empty, run Sol code generation after scaffold
}

// Build runs the initial-build pipeline: scaffold → Sol codegen (if
// instructions present) → docker build → start container. Thin wrapper
// over Execute that handles the build-specific outer lifecycle: load
// or create the agent row, flip agents.status to building, route
// failures into agents.status=failed. Synchronous; caller runs in a
// goroutine.
func (b *BuildService) Build(_ context.Context, input BuildInput) error {
	ctx, cancel := b.startBuild(input.AgentID)
	defer cancel()
	defer b.finishBuild(input.AgentID)

	b.logger.Info("build started",
		zap.String("agent_id", input.AgentID),
		zap.String("slug", input.Slug),
		zap.Bool("has_instructions", input.Instructions != ""))

	q := dbq.New(b.db.Pool())

	var agent dbq.Agent
	var err error

	if input.AgentID != "" {
		agent, err = q.GetAgentByID(ctx, mustParseUUID(input.AgentID))
		if err != nil {
			return fmt.Errorf("get agent: %w", err)
		}
	} else {
		userUUID := mustParseUUID(input.UserID)
		agent, err = q.CreateAgent(ctx, dbq.CreateAgentParams{
			Name:   input.Name,
			Slug:   input.Slug,
			UserID: userUUID,
			Config: []byte("{}"),
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

	if err := q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{
		ID:     agent.ID,
		Status: "building",
	}); err != nil {
		return fmt.Errorf("update status to building: %w", err)
	}

	plan := BuildPlan{
		Agent:       agent,
		Kind:        BuildKindBuild,
		Instruction: input.Instructions,
		Reason:      "manual",
		RunID:       uuid.New().String(),
		Scaffold: &ScaffoldInputs{
			Name:            input.Name,
			Slug:            input.Slug,
			BuildProviderID: input.BuildProviderID,
			BuildModel:      input.BuildModel,
		},
	}
	if _, err := b.Execute(ctx, plan); err != nil {
		status, errMsg := "failed", err.Error()
		if errors.Is(err, context.Canceled) {
			errMsg = "cancelled by user"
			b.logger.Info("build cancelled", zap.String("agent_id", input.AgentID))
		} else {
			b.logger.Error("build failed", zap.String("agent_id", input.AgentID), zap.Error(err))
		}
		_ = q.UpdateAgentStatus(context.Background(), dbq.UpdateAgentStatusParams{
			ID:           agent.ID,
			Status:       status,
			ErrorMessage: errMsg,
		})
		return err
	}
	b.logger.Info("build completed", zap.String("agent_id", input.AgentID))
	return nil
}

// buildCodegenPrompt is the user-turn message for a fresh build. The
// scaffold is empty, so this is a from-scratch implementation request —
// not a spec the model should reconcile a tree against. The agentsdk
// reference lives at /libs/agentsdk/llms.md and is pulled in by the
// system prompt's First Step; this message is just the task.
func buildCodegenPrompt(agent dbq.Agent, instructions string) string {
	return fmt.Sprintf(`Build a new agent from scratch in the scaffolded workspace.

Agent: %s (slug: %s, id: %s)

What it should do:

%s`, agent.Name, agent.Slug, uuidString(agent.ID), instructions)
}

// buildUpgradePrompt is the user-turn message for a codegen upgrade.
// Rebuilds never reach here (doUpgrade branches earlier), so there are
// exactly two intents: a failure-fix (diagnostics present — diagnose
// and repair a crashing agent) or a feature change. Both frame the work
// as incremental against an already-working tree so the model preserves
// everything unrelated. The internal Reason enum is deliberately NOT
// surfaced — it means nothing to the model.
func buildUpgradePrompt(agent dbq.Agent, input UpgradeInput, hasDiagnostics bool) string {
	name := fmt.Sprintf("%s (slug: %s, id: %s)", agent.Name, agent.Slug, uuidString(agent.ID))
	desc := strings.TrimSpace(input.Description)

	if hasDiagnostics {
		p := fmt.Sprintf(`The EXISTING agent %s is failing. Diagnose and fix the failure described in DIAGNOSTICS.md in the workspace. Make the minimal change that fixes it and preserve everything not involved in the fix — do not remove tools, connections, routes, or files unrelated to the failure.`, name)
		if desc != "" {
			p += "\n\nAdditional context from the requester:\n\n" + desc
		}
		return p
	}

	if desc == "" {
		// Degenerate: an auto_fix whose run carried no error context and
		// no description. Don't invent work — just keep it building.
		desc = "(no description provided — make no behavioral changes; only ensure the agent still builds.)"
	}
	return fmt.Sprintf(`You are upgrading the EXISTING agent %s. Its workspace already contains a working codebase. This is an incremental change request — implement it and preserve everything not related to it. Do not remove tools, connections, routes, or files the request doesn't mention.

Requested change:

%s`, name, desc)
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

// createAgentSchema creates a dedicated Postgres role and schema for the agent.
// Returns the plaintext DB password for the role.
func (b *BuildService) createAgentSchema(ctx context.Context, agentID, schemaName string) (string, error) {
	conn, err := b.db.Pool().Acquire(ctx)
	if err != nil {
		return "", fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	// Generate random password.
	pwBytes := make([]byte, 32)
	if _, err := rand.Read(pwBytes); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	password := hex.EncodeToString(pwBytes)

	roleName := schemaName // e.g. agent_<uuid_no_hyphens>

	// Create role via SECURITY DEFINER function (avoids granting CREATEROLE to airlock_app).
	_, err = conn.Exec(ctx, "SELECT create_agent_role($1, $2)", roleName, password)
	if err != nil {
		return "", fmt.Errorf("create role: %w", err)
	}

	// Create schema owned by the agent role.
	_, err = conn.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s AUTHORIZATION %s", schemaName, roleName))
	if err != nil {
		return "", fmt.Errorf("create schema: %w", err)
	}

	return password, nil
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
		roleName, url.QueryEscape(password), b.cfg.DBHostAgent, b.cfg.DBPort,
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
func (b *BuildService) agentDBURLBase(host, roleName, password string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		roleName, url.QueryEscape(password), host, b.cfg.DBPort,
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
		"-e", "AIRLOCK_DB_URL=" + dbURL,
		"-e", "AIRLOCK_AGENT_ID=rollback",
		"-e", "AIRLOCK_API_URL=http://invalid-not-used-in-down-mode",
		"-e", "AIRLOCK_AGENT_TOKEN=rollback",
	}
	if b.cfg.DockerNetwork != "" {
		args = append(args, "--network", b.cfg.DockerNetwork)
	}
	args = append(args, imageTag)

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("down-to %d failed: %w\n%s", targetVersion, err, string(out))
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
		"-e", "AIRLOCK_DB_URL=" + dbURL,
		"-e", "AIRLOCK_AGENT_ID=validate",
		"-e", "AIRLOCK_API_URL=http://invalid-not-used-in-validate-mode",
		"-e", "AIRLOCK_AGENT_TOKEN=validate",
	}
	if b.cfg.DockerNetwork != "" {
		args = append(args, "--network", b.cfg.DockerNetwork)
	}
	args = append(args, imageTag)

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("migration validation failed: %w\n%s", err, string(out))
	}
	logLine("Migrations validated successfully")
	return nil
}

// cloneSchema creates a copy of an agent's schema for safe upgrade testing.
// roleName is the agent's Postgres role to grant access to the clone.
func (b *BuildService) cloneSchema(ctx context.Context, sourceSchema, cloneName, roleName string) error {
	conn, err := b.db.Pool().Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	// Create the clone schema
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s", cloneName)); err != nil {
		return fmt.Errorf("create clone schema: %w", err)
	}

	// Get tables from source schema
	rows, err := conn.Query(ctx,
		"SELECT tablename FROM pg_tables WHERE schemaname = $1", sourceSchema)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return fmt.Errorf("scan table: %w", err)
		}
		tables = append(tables, t)
	}

	// Copy each table's structure and data
	for _, t := range tables {
		_, err := conn.Exec(ctx, fmt.Sprintf(
			"CREATE TABLE %s.%s AS TABLE %s.%s",
			cloneName, t, sourceSchema, t))
		if err != nil {
			return fmt.Errorf("clone table %s: %w", t, err)
		}
	}

	// Transfer ownership to the agent role.
	//
	// GRANT ALL covers SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER
	// but NOT DROP TABLE — DDL on a table is gated on ownership in Postgres,
	// not privileges. Without these ALTER OWNER calls the agent's migration
	// validation (up → down → up) fails on the down step with
	// "must be owner of table X (42501)" because the cloned tables are
	// still owned by whoever the airlock pool connected as. Owning the
	// schema also makes subsequent CREATE TABLE during the migration up
	// inherit the agent role as owner, so newly-created and cloned tables
	// are uniformly droppable on the way down.
	if _, err := conn.Exec(ctx, fmt.Sprintf("ALTER SCHEMA %s OWNER TO %s", cloneName, roleName)); err != nil {
		return fmt.Errorf("alter schema owner: %w", err)
	}
	for _, t := range tables {
		if _, err := conn.Exec(ctx, fmt.Sprintf(
			"ALTER TABLE %s.%s OWNER TO %s", cloneName, t, roleName)); err != nil {
			return fmt.Errorf("alter table owner %s: %w", t, err)
		}
	}

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

// RecoverStuckOperations resets any builds or upgrades left in progress
// after an unclean shutdown. Should be called on startup.
func (b *BuildService) RecoverStuckOperations(ctx context.Context) error {
	q := dbq.New(b.db.Pool())

	msg := "interrupted by Airlock restart"
	if err := q.ResetStuckBuilds(ctx, msg); err != nil {
		return fmt.Errorf("reset stuck builds: %w", err)
	}

	if err := q.ResetStuckAgentBuilds(ctx); err != nil {
		return fmt.Errorf("reset stuck agent builds: %w", err)
	}

	if err := q.ResetStuckUpgrades(ctx); err != nil {
		return fmt.Errorf("reset stuck upgrades: %w", err)
	}

	if err := q.ResetStuckRuns(ctx, msg); err != nil {
		return fmt.Errorf("reset stuck runs: %w", err)
	}

	// Drop orphaned upgrade schema clones
	if err := b.dropOrphanedSchemas(ctx); err != nil {
		b.logger.Warn("failed to drop orphaned schemas", zap.Error(err))
	}

	return nil
}

// dropOrphanedSchemas drops upgrade schema clones left from crashed operations.
func (b *BuildService) dropOrphanedSchemas(ctx context.Context) error {
	conn, err := b.db.Pool().Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	rows, err := conn.Query(ctx,
		"SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'agent_%_upgrade_%'")
	if err != nil {
		return err
	}
	defer rows.Close()

	var schemas []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return err
		}
		schemas = append(schemas, s)
	}

	for _, s := range schemas {
		b.logger.Info("dropping orphaned schema", zap.String("schema", s))
		if _, err := conn.Exec(ctx, fmt.Sprintf("DROP SCHEMA %s CASCADE", s)); err != nil {
			b.logger.Warn("failed to drop orphaned schema", zap.String("schema", s), zap.Error(err))
		}
	}

	return nil
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
