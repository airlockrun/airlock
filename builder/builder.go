package builder

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/scaffold"
	"github.com/airlockrun/goai/tool"
	sol "github.com/airlockrun/sol"
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
	cfg              *config.Config
	db               *db.DB
	containers       container.ContainerManager
	encryptor        *crypto.Encryptor
	events           EventPublisher
	upgradeNotifier  PostUpgradeNotifier
	logger           *zap.Logger

	mu          sync.Mutex
	cancelFuncs map[string]context.CancelFunc // agentID → cancel running build/upgrade
}

// New creates a BuildService. Panics if any dependency is nil.
func New(cfg *config.Config, database *db.DB, containers container.ContainerManager, encryptor *crypto.Encryptor, logger *zap.Logger) *BuildService {
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
	return &BuildService{
		cfg:         cfg,
		db:          database,
		containers:  containers,
		encryptor:   encryptor,
		events:      noopPublisher{},
		logger:      logger,
		cancelFuncs: make(map[string]context.CancelFunc),
	}
}

// MonorepoPath returns the agent monorepo path.
func (b *BuildService) MonorepoPath() string {
	return b.cfg.AgentMonorepoPath
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
	b.cancelFuncs[agentID] = cancel
	b.mu.Unlock()
	return ctx, cancel
}

// finishBuild removes the cancel func for a completed build.
func (b *BuildService) finishBuild(agentID string) {
	b.mu.Lock()
	delete(b.cancelFuncs, agentID)
	b.mu.Unlock()
}

// CancelBuild cancels a running build/upgrade for the given agent.
// Returns true if a build was running and cancelled.
func (b *BuildService) CancelBuild(agentID string) bool {
	b.mu.Lock()
	cancel, ok := b.cancelFuncs[agentID]
	delete(b.cancelFuncs, agentID)
	b.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// BuildInput describes what to build.
type BuildInput struct {
	AgentID      string
	Name         string
	Slug         string
	UserID       string
	BuildModel   string // stored on agent for future upgrades
	Instructions string // optional: when non-empty, run Sol code generation after scaffold
}

// Build runs the full build pipeline: scaffold → Sol code gen → compile → containerize → deploy.
// This is synchronous — caller should run in a goroutine if needed.
// If input.AgentID is set, uses the existing agent record (created by the API handler for async 202 responses).
// If empty, creates a new agent record.
func (b *BuildService) Build(_ context.Context, input BuildInput) error {
	ctx, cancel := b.startBuild(input.AgentID)
	defer cancel()
	defer b.finishBuild(input.AgentID)

	q := dbq.New(b.db.Pool())

	var agent dbq.Agent
	var err error

	if input.AgentID != "" {
		// Use pre-created agent record.
		agent, err = q.GetAgentByID(ctx, mustParseUUID(input.AgentID))
		if err != nil {
			return fmt.Errorf("get agent: %w", err)
		}
	} else {
		// Create agent record. Model overrides default to empty strings
		// (live inheritance from system_settings); set BuildModel if the
		// caller picked one explicitly.
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
				ID:         agent.ID,
				BuildModel: input.BuildModel,
			})
			agent.BuildModel = input.BuildModel
		}
	}

	// Update status to building
	if err := q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{
		ID:     agent.ID,
		Status: "building",
	}); err != nil {
		return fmt.Errorf("update status to building: %w", err)
	}

	agentUUID := uuid.UUID(agent.ID.Bytes)

	// Create the agent_builds record up-front so we can include its ID in
	// the "started" event. The frontend uses this to fetch the REST snapshot.
	build, err := q.CreateAgentBuild(ctx, dbq.CreateAgentBuildParams{
		AgentID:      agent.ID,
		Type:         "build",
		Instructions: input.Instructions,
	})
	if err != nil {
		return fmt.Errorf("create build record: %w", err)
	}
	buildUUID := uuid.UUID(build.ID.Bytes)

	b.events.PublishBuildEvent(ctx, agentUUID, buildUUID, "started", "")

	// From here, failures should set status to failed.
	// Use background context for DB updates — the build context may be cancelled.
	dbCtx := context.Background()
	if err := b.doBuild(ctx, q, agent, build, input.Instructions); err != nil {
		status, event := "failed", "failed"
		errMsg := err.Error()
		if errors.Is(err, context.Canceled) {
			status = "failed"
			event = "cancelled"
			errMsg = "cancelled by user"
		}
		_ = q.UpdateAgentStatus(dbCtx, dbq.UpdateAgentStatusParams{
			ID:           agent.ID,
			Status:       status,
			ErrorMessage: errMsg,
		})
		b.events.PublishBuildEvent(dbCtx, agentUUID, buildUUID, event, errMsg)
		return err
	}

	b.events.PublishBuildEvent(dbCtx, agentUUID, buildUUID, "complete", "")
	return nil
}

// doBuild runs the build steps after the agent record is created.
// If instructions are provided, runs Sol code generation after scaffolding.
func (b *BuildService) doBuild(ctx context.Context, q *dbq.Queries, agent dbq.Agent, build dbq.AgentBuild, instructions string) error {
	repoPath := b.cfg.AgentMonorepoPath
	agentID := uuidString(agent.ID)
	agentUUID := uuid.UUID(agent.ID.Bytes)
	buildUUID := uuid.UUID(build.ID.Bytes)

	bl := newBuildLog(q, build.ID, b.logger)
	defer bl.close()

	solLog := func(line string) {
		seq := bl.appendSol(line)
		b.events.PublishBuildLogLine(ctx, agentUUID, buildUUID, seq, "sol", line)
	}
	dockerLog := func(line string) {
		seq := bl.appendDocker(line)
		b.events.PublishBuildLogLine(ctx, agentUUID, buildUUID, seq, "docker", line)
	}
	// logLine is a top-level progress messages (step headers). Route to the sol stream.
	logLine := solLog

	completeBuild := func(status, errMsg, sourceRef, imageRef string) {
		_ = q.UpdateAgentBuildComplete(context.Background(), dbq.UpdateAgentBuildCompleteParams{
			ID:           build.ID,
			Status:       status,
			ErrorMessage: errMsg,
			SourceRef:    sourceRef,
			ImageRef:     imageRef,
		})
	}

	// Step 1: Init monorepo
	logLine("Initializing monorepo...")
	if err := InitMonorepo(repoPath); err != nil {
		completeBuild("failed", err.Error(), "", "")
		return fmt.Errorf("init monorepo: %w", err)
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", "", "")
		return ctx.Err()
	}

	// Step 2: Scaffold
	logLine("Scaffolding agent...")
	data := scaffold.ScaffoldData{
		AgentID:   agentID,
		Module:    "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v" + agentsdk.Version,
	}
	commitHash, err := CommitScaffold(repoPath, agentID, data)
	if err != nil {
		completeBuild("failed", err.Error(), "", "")
		return fmt.Errorf("commit scaffold: %w", err)
	}
	b.logger.Info("scaffold committed", zap.String("agent", agentID), zap.String("commit", commitHash))

	// Step 3: Merge scaffold branch to main
	logLine("Merging scaffold to main...")
	branch := fmt.Sprintf("build/%s/init", agentID)
	if err := MergeBranch(repoPath, branch); err != nil {
		completeBuild("failed", err.Error(), "", "")
		return fmt.Errorf("merge to main: %w", err)
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", "", "")
		return ctx.Err()
	}

	// Step 4: Create agent DB role + schema (before Sol so we can create a test clone)
	schemaName := fmt.Sprintf("agent_%s", sanitizeUUID(agentID))
	dbPassword, err := b.createAgentSchema(ctx, agentID, schemaName)
	if err != nil {
		completeBuild("failed", err.Error(), "", "")
		return fmt.Errorf("create schema: %w", err)
	}

	// Encrypt and store DB password in agent config
	encPassword, err := b.encryptor.Encrypt(dbPassword)
	if err != nil {
		completeBuild("failed", err.Error(), "", "")
		return fmt.Errorf("encrypt db password: %w", err)
	}
	agentConfig, _ := json.Marshal(map[string]string{"db_password": encPassword})
	if err := q.UpdateAgentConfig(ctx, dbq.UpdateAgentConfigParams{
		ID:     agent.ID,
		Config: agentConfig,
	}); err != nil {
		completeBuild("failed", err.Error(), "", "")
		return fmt.Errorf("update agent config: %w", err)
	}

	// Step 5: Create a test clone for Sol to validate migrations against.
	testClone := fmt.Sprintf("agent_%s_test_%s", sanitizeUUID(agentID), hex.EncodeToString(func() []byte { b := make([]byte, 4); rand.Read(b); return b }()))
	if err := b.cloneSchema(ctx, schemaName, testClone, schemaName); err != nil {
		completeBuild("failed", err.Error(), "", "")
		return fmt.Errorf("create test clone: %w", err)
	}
	defer b.dropSchemaClone(ctx, testClone)

	testDBURL := b.agentDBURL(schemaName, dbPassword, testClone)
	testDBPSQL := b.agentDBURLBase(b.cfg.DBHostAgent, schemaName, dbPassword)
	testDBSchema := testClone

	// Step 6 (optional): Run Sol code generation if instructions are provided.
	if instructions != "" {
		logLine("Running Sol code generation...")
		solHash, err := b.runBuildCodegen(ctx, q, agent, agentID, agentUUID, instructions, testDBURL, testDBPSQL, testDBSchema, solLog)
		if err != nil {
			completeBuild("failed", err.Error(), "", "")
			return fmt.Errorf("sol codegen: %w", err)
		}
		commitHash = solHash
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", commitHash, "")
		return ctx.Err()
	}

	// Step 7: Build Docker image
	logLine("Building Docker image...")
	contextDir := filepath.Join(repoPath, "agents", agentID)
	if err := scaffold.GenerateDockerfile(contextDir, scaffold.ScaffoldData{
		AgentID:   agentID,
		Module:    "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v" + agentsdk.Version,
	}); err != nil {
		completeBuild("failed", err.Error(), commitHash, "")
		return fmt.Errorf("generate Dockerfile: %w", err)
	}
	imageTag, err := buildImage(ctx, b.cfg, agentID, contextDir, commitHash, dockerLog)
	if err != nil {
		completeBuild("failed", err.Error(), commitHash, "")
		return fmt.Errorf("build image: %w", err)
	}
	b.logger.Info("image built", zap.String("image", imageTag))

	// Step 8: Validate migrations by running the image with AGENT_VALIDATE_MIGRATIONS=1.
	// Uses the agent-network DB URL since the container runs on the Docker network.
	agentTestDBURL := b.agentDBURL(schemaName, dbPassword, testClone)
	if err := b.validateMigrations(ctx, imageTag, agentTestDBURL, logLine); err != nil {
		completeBuild("failed", err.Error(), commitHash, imageTag)
		return fmt.Errorf("migration validation: %w", err)
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", commitHash, imageTag)
		return ctx.Err()
	}

	// Step 9: Start agent container
	logLine("Starting agent container...")
	agentToken, err := auth.IssueAgentToken(b.cfg.JWTSecret, agentUUID)
	if err != nil {
		completeBuild("failed", err.Error(), commitHash, imageTag)
		return fmt.Errorf("issue agent token: %w", err)
	}
	agentDBURL := b.agentDBURL(schemaName, dbPassword, schemaName)
	c, err := b.containers.StartAgent(ctx, container.AgentOpts{
		AgentID: agentUUID,
		Image:   imageTag,
		Env: map[string]string{
			"AIRLOCK_AGENT_ID":    agentID,
			"AIRLOCK_API_URL":     b.cfg.APIURLAgent,
			"AIRLOCK_DB_URL":      agentDBURL,
			"AIRLOCK_AGENT_TOKEN": agentToken,
		},
	})
	if err != nil {
		completeBuild("failed", err.Error(), commitHash, imageTag)
		return fmt.Errorf("start agent: %w", err)
	}
	b.logger.Info("agent started", zap.String("endpoint", c.Endpoint))

	// Step 8: Update agent record
	if err := q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{
		ID:     agent.ID,
		Status: "active",
	}); err != nil {
		return fmt.Errorf("update status to active: %w", err)
	}
	if err := q.UpdateAgentRefs(ctx, dbq.UpdateAgentRefsParams{
		ID:        agent.ID,
		SourceRef: commitHash,
		ImageRef:  imageTag,
	}); err != nil {
		return fmt.Errorf("update refs: %w", err)
	}

	completeBuild("complete", "", commitHash, imageTag)
	return nil
}

// runBuildCodegen runs Sol code generation on a freshly scaffolded agent.
// Creates a branch, sparse checkouts the agent dir, writes AGENT_SPEC.md,
// runs Sol, commits, merges back to main. Returns the new commit hash.
func (b *BuildService) runBuildCodegen(ctx context.Context, q *dbq.Queries, agent dbq.Agent, agentID string, agentUUID uuid.UUID, instructions string, testDBURL, testDBPSQL, testDBSchema string, logLine func(string)) (string, error) {
	repoPath := b.cfg.AgentMonorepoPath

	// Create a codegen branch from main.
	codegenBranch := fmt.Sprintf("build/%s/codegen", agentID)
	if err := CreateBranch(repoPath, codegenBranch); err != nil {
		return "", fmt.Errorf("create codegen branch: %w", err)
	}

	// Sparse checkout into a temp dir.
	workDir, err := os.MkdirTemp("", "airlock-codegen-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	if err := SparseCheckout(repoPath, codegenBranch, agentID, workDir); err != nil {
		return "", fmt.Errorf("sparse checkout: %w", err)
	}

	// Write AGENT_SPEC.md with build instructions.
	agentDir := filepath.Join(workDir, "agents", agentID)
	if err := b.writeBuildSpec(agentDir, agent, instructions); err != nil {
		return "", fmt.Errorf("write build spec: %w", err)
	}

	// Run Sol in-process.
	localTools := tool.Set{}
	localTools.Add(newMCPProbeTool())

	solResult, err := b.runSolInProcess(ctx, solRunOpts{
		WorkDir:    workDir,
		AgentDir:   fmt.Sprintf("/workspace/agents/%s", agentID),
		BuildModel: agent.BuildModel,
		Prompt:     "Implement the agent according to the specification. Read AGENT_SPEC.md for details.",
		LocalTools: localTools,
		TestDBURL:    testDBURL,
		TestDBPSQL:   testDBPSQL,
		TestDBSchema: testDBSchema,
		LogCallback: func(line string) {
			logLine(line)
		},
	})
	if err != nil {
		return "", fmt.Errorf("sol run: %w", err)
	}
	if solResult.Status != sol.RunCompleted {
		errMsg := "unknown error"
		if solResult.Error != nil {
			errMsg = solResult.Error.Error()
		}
		return "", fmt.Errorf("sol codegen failed: %s", errMsg)
	}

	// Commit and push back to monorepo.
	hash, err := CommitAndPush(workDir, fmt.Sprintf("codegen agent %s", agentID))
	if err != nil {
		return "", fmt.Errorf("commit codegen: %w", err)
	}

	// Merge codegen branch to main.
	if err := MergeBranch(repoPath, codegenBranch); err != nil {
		return "", fmt.Errorf("merge codegen: %w", err)
	}

	return hash, nil
}

// writeBuildSpec writes AGENT_SPEC.md for initial code generation.
func (b *BuildService) writeBuildSpec(dir string, agent dbq.Agent, instructions string) error {
	content := fmt.Sprintf(`# Agent Specification

## Identity

- **Name:** %s
- **Slug:** %s
- **ID:** %s

## Instructions

%s
`, agent.Name, agent.Slug, uuidString(agent.ID), instructions)

	return os.WriteFile(filepath.Join(dir, "AGENT_SPEC.md"), []byte(content), 0o644)
}

// writeUpgradeSpec writes AGENT_SPEC.md for an upgrade to the agent workspace directory.
func (b *BuildService) writeUpgradeSpec(dir string, agent dbq.Agent, input UpgradeInput) error {
	content := fmt.Sprintf(`# Agent Specification

## Identity

- **Name:** %s
- **Slug:** %s
- **ID:** %s

## Description

%s

## Upgrade Context

- **Reason:** %s
- **Description:** %s
`, agent.Name, agent.Slug, uuidString(agent.ID), agent.Description, input.Reason, input.Description)

	if input.ErrorMessage != "" {
		content += fmt.Sprintf("\n### Error Message\n\n```\n%s\n```\n", input.ErrorMessage)
	}
	if input.PanicTrace != "" {
		content += fmt.Sprintf("\n### Panic Trace\n\n```\n%s\n```\n", input.PanicTrace)
	}
	if input.InputPayload != "" {
		content += fmt.Sprintf("\n### Failed Input\n\n```json\n%s\n```\n", input.InputPayload)
	}
	if input.Actions != "" {
		content += fmt.Sprintf("\n### Recorded Actions\n\n```json\n%s\n```\n", input.Actions)
	}
	if input.Messages != "" {
		content += fmt.Sprintf("\n### Conversation Messages\n\n```\n%s\n```\n", input.Messages)
	}

	return os.WriteFile(filepath.Join(dir, "AGENT_SPEC.md"), []byte(content), 0o644)
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
func (b *BuildService) agentDBURL(roleName, password, schemaName string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?search_path=%s&sslmode=%s",
		roleName, url.QueryEscape(password), b.cfg.DBHostAgent, b.cfg.DBPort,
		b.cfg.DBName, schemaName, b.cfg.DBSSLMode)
}

// agentDBURLLocal builds a Postgres connection URL using DBHost.
// Used for build-time migration validation which runs in the Airlock process.
func (b *BuildService) agentDBURLLocal(roleName, password, schemaName string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?search_path=%s&sslmode=%s",
		roleName, url.QueryEscape(password), b.cfg.DBHost, b.cfg.DBPort,
		b.cfg.DBName, schemaName, b.cfg.DBSSLMode)
}

// agentDBURLBase builds a Postgres connection URL without search_path.
// Used for psql which doesn't support search_path as a URI parameter.
func (b *BuildService) agentDBURLBase(host, roleName, password string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		roleName, url.QueryEscape(password), host, b.cfg.DBPort,
		b.cfg.DBName, b.cfg.DBSSLMode)
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

	// Grant agent role access to the clone schema
	if _, err := conn.Exec(ctx, fmt.Sprintf("GRANT ALL ON SCHEMA %s TO %s", cloneName, roleName)); err != nil {
		return fmt.Errorf("grant clone access: %w", err)
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("GRANT ALL ON ALL TABLES IN SCHEMA %s TO %s", cloneName, roleName)); err != nil {
		return fmt.Errorf("grant clone table access: %w", err)
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
