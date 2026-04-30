package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/scaffold"
	sol "github.com/airlockrun/sol"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PostUpgradeNotifier is called after an upgrade finishes (success or
// failure) to post a single message into the originating conversation.
//
// status is "success" or "error". message is the human-readable text to
// surface — typically sourced from the agent-builder's exit tool on
// success, or the underlying failure reason on error. The notifier
// posts exactly ONE message and does not trigger a follow-up LLM turn —
// the agent's own exit-tool summary already describes the outcome, so
// re-prompting just produces redundant text.
type PostUpgradeNotifier interface {
	NotifyUpgradeComplete(ctx context.Context, agentID uuid.UUID, conversationID, status, message string) error
}

// UpgradeInput describes an upgrade request.
type UpgradeInput struct {
	AgentID        string
	RunID          string // the run that triggered the upgrade
	Reason         string // "llm_request", "auto_fix", "manual"
	Description    string // what to change
	ConversationID string // conversation that triggered the upgrade (for post-upgrade reply)
	ErrorMessage   string // from failed run (auto_fix)
	PanicTrace     string // from failed run (auto_fix)
	InputPayload   string // JSON of failed run input (auto_fix)
	Actions        string // JSON of recorded actions before failure (auto_fix)
	Messages       string // conversation messages from the failed run
}

// Upgrade runs the upgrade pipeline for an existing agent.
// This is synchronous — caller should run in a goroutine if needed.
// AcquireUpgradeLock atomically checks that no upgrade is running for the
// agent and sets upgrade_status to "building". Returns ErrUpgradeInProgress
// if an upgrade is already active. Call RunUpgrade after a successful lock.
func (b *BuildService) AcquireUpgradeLock(ctx context.Context, agentID string) error {
	q := dbq.New(b.db.Pool())
	agentPgUUID := mustParseUUID(agentID)

	tx, err := b.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	qtx := q.WithTx(tx)

	row, err := qtx.GetAgentForUpgrade(ctx, agentPgUUID)
	if err != nil {
		tx.Rollback(ctx)
		return fmt.Errorf("get agent for upgrade: %w", err)
	}

	if row.UpgradeStatus != "idle" && row.UpgradeStatus != "failed" {
		tx.Rollback(ctx)
		return ErrUpgradeInProgress
	}

	if err := qtx.UpdateAgentUpgradeStatus(ctx, dbq.UpdateAgentUpgradeStatusParams{
		ID:            agentPgUUID,
		UpgradeStatus: "building",
		ErrorMessage:  "",
	}); err != nil {
		tx.Rollback(ctx)
		return fmt.Errorf("set upgrade status: %w", err)
	}
	return tx.Commit(ctx)
}

// RunUpgrade executes the upgrade pipeline for an agent that already has
// its upgrade_status set to "building" via AcquireUpgradeLock.
func (b *BuildService) RunUpgrade(_ context.Context, input UpgradeInput) {
	ctx, cancel := b.startBuild(input.AgentID)
	defer cancel()
	defer b.finishBuild(input.AgentID)

	if input.RunID == "" {
		input.RunID = uuid.New().String()
	}

	b.logger.Info("upgrade started",
		zap.String("agent_id", input.AgentID),
		zap.String("run_id", input.RunID),
		zap.String("reason", input.Reason))

	q := dbq.New(b.db.Pool())
	agentPgUUID := mustParseUUID(input.AgentID)
	agentUUID, _ := uuid.Parse(input.AgentID)
	dbCtx := context.Background() // for DB updates after cancellation

	// Create the agent_builds record up-front so the "started" event can
	// carry its ID (frontend uses it to fetch the REST snapshot).
	upgradeInstructions := fmt.Sprintf("Reason: %s\nDescription: %s", input.Reason, input.Description)
	if input.ErrorMessage != "" {
		upgradeInstructions += fmt.Sprintf("\nError: %s", input.ErrorMessage)
	}
	if input.Messages != "" {
		upgradeInstructions += fmt.Sprintf("\nMessages:\n%s", input.Messages)
	}
	build, err := q.CreateAgentBuild(ctx, dbq.CreateAgentBuildParams{
		AgentID:      agentPgUUID,
		Type:         "upgrade",
		Instructions: upgradeInstructions,
	})
	if err != nil {
		b.logger.Error("create upgrade build record", zap.Error(err))
		return
	}
	buildUUID := uuid.UUID(build.ID.Bytes)

	b.events.PublishBuildEvent(ctx, agentUUID, buildUUID, "started", "")

	successMsg, err := b.doUpgrade(ctx, q, input, build)
	if err != nil {
		event := "failed"
		errMsg := err.Error()
		if errors.Is(err, context.Canceled) {
			event = "cancelled"
			errMsg = "cancelled by user"
			b.logger.Info("upgrade cancelled", zap.String("agent_id", input.AgentID))
		} else {
			b.logger.Error("upgrade failed", zap.String("agent_id", input.AgentID), zap.Error(err))
		}
		_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
			ID:            agentPgUUID,
			UpgradeStatus: "failed",
			ErrorMessage:  errMsg,
		})
		b.events.PublishBuildEvent(dbCtx, agentUUID, buildUUID, event, errMsg)
		// Surface the failure as a single conversation message too —
		// previously the user only saw "still spinning" then nothing.
		// Cancellation skips the notification (the cancel button toast
		// already covered it).
		if event != "cancelled" && input.ConversationID != "" && b.upgradeNotifier != nil {
			if nerr := b.upgradeNotifier.NotifyUpgradeComplete(dbCtx, agentUUID, input.ConversationID, "error", errMsg); nerr != nil {
				b.logger.Error("post-upgrade error notification failed", zap.Error(nerr))
			}
		}
		return
	}

	b.logger.Info("upgrade completed", zap.String("agent_id", input.AgentID))
	b.events.PublishBuildEvent(dbCtx, agentUUID, buildUUID, "complete", "")

	_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
		ID:            agentPgUUID,
		UpgradeStatus: "idle",
		ErrorMessage:  "",
	})

	// Notify the originating conversation. Single message — the
	// agent-builder's exit tool already produced the user-facing summary
	// (successMsg), so no LLM follow-up turn is needed.
	if input.ConversationID != "" && b.upgradeNotifier != nil {
		// Fall back to the user's original description if the agent
		// somehow returned an empty exit message (shouldn't happen with
		// the nudge loop, but cheap defense).
		msg := successMsg
		if msg == "" {
			msg = "Upgrade complete: " + input.Description
		}
		if err := b.upgradeNotifier.NotifyUpgradeComplete(dbCtx, agentUUID, input.ConversationID, "success", msg); err != nil {
			b.logger.Error("post-upgrade notification failed", zap.Error(err))
		}
	}
}

// doUpgrade returns the agent-builder's exit-tool success message
// alongside the err. Caller plumbs successMsg into the conversation
// notification so the user sees the agent's own summary of what
// changed instead of the canned "Upgrade complete: <description>" we
// used to post.
func (b *BuildService) doUpgrade(ctx context.Context, q *dbq.Queries, input UpgradeInput, build dbq.AgentBuild) (string, error) {
	agentPgUUID := mustParseUUID(input.AgentID)
	agentID := input.AgentID
	repoPath := b.cfg.AgentMonorepoPath
	buildUUID := uuid.UUID(build.ID.Bytes)

	// Load full agent record
	agent, err := q.GetAgentByID(ctx, agentPgUUID)
	if err != nil {
		return "", fmt.Errorf("get agent: %w", err)
	}

	agentUUID, _ := uuid.Parse(agentID)

	bl := newBuildLog(q, build.ID, b.logger)
	defer bl.close()

	completeBuild := func(status, errMsg, sourceRef, imageRef string) {
		_ = q.UpdateAgentBuildComplete(context.Background(), dbq.UpdateAgentBuildCompleteParams{
			ID:           build.ID,
			Status:       status,
			ErrorMessage: errMsg,
			SourceRef:    sourceRef,
			ImageRef:     imageRef,
		})
	}

	// Step 2: Clone schema for safe upgrade testing + migration validation.
	sourceSchema := fmt.Sprintf("agent_%s", sanitizeUUID(agentID))
	cloneName := fmt.Sprintf("agent_%s_upgrade_%s", sanitizeUUID(agentID), sanitizeUUID(input.RunID))
	if err := b.cloneSchema(ctx, sourceSchema, cloneName, sourceSchema); err != nil {
		return "", fmt.Errorf("clone schema: %w", err)
	}
	defer func() {
		if err := b.dropSchemaClone(ctx, cloneName); err != nil {
			b.logger.Warn("failed to drop clone schema", zap.Error(err))
		}
	}()

	// Decrypt DB password (needed for test URL and later for container start).
	var agentConfig map[string]string
	json.Unmarshal(agent.Config, &agentConfig)
	dbPassword, err := b.encryptor.Decrypt(agentConfig["db_password"])
	if err != nil {
		return "", fmt.Errorf("decrypt db password: %w", err)
	}
	testDBURL := b.agentDBURL(sourceSchema, dbPassword, cloneName)

	// Step 3: Create upgrade branch
	if err := CreateUpgradeBranch(repoPath, agentID, input.RunID); err != nil {
		return "", fmt.Errorf("create upgrade branch: %w", err)
	}

	// Step 4: Sparse checkout
	workDir, err := b.makeCodegenTempDir("airlock-upgrade-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	branch := fmt.Sprintf("upgrade/%s/%s", agentID, input.RunID)
	if err := SparseCheckout(repoPath, branch, agentID, workDir); err != nil {
		return "", fmt.Errorf("sparse checkout: %w", err)
	}

	// Step 5: Write upgrade spec
	agentDir := filepath.Join(workDir, "agents", agentID)
	if err := b.writeUpgradeSpec(agentDir, agent, input); err != nil {
		return "", fmt.Errorf("write upgrade spec: %w", err)
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", "", "")
		return "", ctx.Err()
	}

	// Step 6: Run Sol. Pass the agent's build model verbatim — empty
	// string is fine, runSolInProcess falls back to the system-wide
	// default (settings.default_build_model) when no per-agent override
	// is set.
	logLine := func(line string) {
		seq := bl.appendSol(line)
		b.events.PublishBuildLogLine(ctx, agentUUID, buildUUID, seq, "sol", line)
	}

	solResult, err := b.runSolInProcess(ctx, solRunOpts{
		WorkDir:    workDir,
		AgentDir:   fmt.Sprintf("/workspace/agents/%s", agentID),
		BuildModel: agent.BuildModel,
		Prompt:     "Fix/upgrade the agent. Read AGENT_SPEC.md for the specification and error context.",
		TestDBURL:    testDBURL,
		TestDBPSQL:   b.agentDBURLBase(b.cfg.DBHostAgent, sourceSchema, dbPassword),
		TestDBSchema: cloneName,
		LogCallback:  logLine,
	})
	if err != nil {
		completeBuild("failed", err.Error(), "", "")
		return "", fmt.Errorf("sol upgrade: %w", err)
	}

	// Step 7: Check result. Same exit-tool mapping as runBuildCodegen —
	// see that function for the full rationale.
	if solResult.Status != sol.RunExited {
		if solResult.Status == sol.RunCompleted {
			b.logger.Error("sol upgrade did not call exit tool")
			completeBuild("failed", "agent did not call the exit tool", "", "")
			return "", errors.New("upgrade failed: agent did not call the exit tool")
		}
		errMsg := "unknown error"
		if solResult.Error != nil {
			errMsg = solResult.Error.Error()
		}
		b.logger.Error("sol upgrade failed", zap.String("status", string(solResult.Status)), zap.String("error", errMsg))
		completeBuild("failed", errMsg, "", "")
		if solResult.Error != nil {
			return "", fmt.Errorf("upgrade failed: %w", solResult.Error)
		}
		return "", errors.New("upgrade failed")
	}
	if solResult.ExitStatus != "success" {
		b.logger.Error("sol upgrade reported error", zap.String("message", solResult.ExitMessage))
		completeBuild("failed", solResult.ExitMessage, "", "")
		// Return the exit message verbatim — the conversation
		// notification reads err.Error() and surfaces it as the
		// "agent reports it failed because…" line for the user.
		return "", errors.New(solResult.ExitMessage)
	}

	// Step 9: Commit and push
	hash, err := CommitAndPush(workDir, fmt.Sprintf("upgrade agent %s: %s", agentID, input.Reason))
	if err != nil {
		completeBuild("failed", err.Error(), "", "")
		return "", fmt.Errorf("commit upgrade: %w", err)
	}
	b.logger.Info("upgrade committed", zap.String("commit", hash))

	// Step 10: Merge
	if err := MergeBranch(repoPath, branch); err != nil {
		completeBuild("failed", err.Error(), "", "")
		return "", fmt.Errorf("merge upgrade: %w", err)
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", hash, "")
		return "", ctx.Err()
	}

	// Step 11: Build image
	contextDir := filepath.Join(repoPath, "agents", agentID)
	if err := scaffold.GenerateDockerfile(contextDir, scaffold.ScaffoldData{
		AgentID:   agentID,
		Module:    "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v" + agentsdk.Version,
	}); err != nil {
		completeBuild("failed", err.Error(), hash, "")
		return "", fmt.Errorf("generate Dockerfile: %w", err)
	}
	// Bump the agent's go.mod require line to the current SDK version so
	// gopls/editor tooling shows what the build is actually linking against
	// (the replace directive shadows it for compilation).
	if err := bumpAgentSDKRequire(ctx, contextDir, agentsdk.Version); err != nil {
		completeBuild("failed", err.Error(), hash, "")
		return "", fmt.Errorf("bump agent SDK require: %w", err)
	}
	imageTag, err := buildImage(ctx, b.cfg, agentID, contextDir, hash, func(line string) {
		seq := bl.appendDocker(line)
		b.events.PublishBuildLogLine(ctx, agentUUID, buildUUID, seq, "docker", line)
	})
	if err != nil {
		completeBuild("failed", err.Error(), hash, "")
		return "", fmt.Errorf("build image: %w", err)
	}

	// Validate migrations against the clone schema by running the new image.
	upgradeTestDBURL := b.agentDBURL(sourceSchema, dbPassword, cloneName)
	if err := b.validateMigrations(ctx, imageTag, upgradeTestDBURL, logLine); err != nil {
		completeBuild("failed", err.Error(), hash, imageTag)
		return "", fmt.Errorf("migration validation: %w", err)
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", hash, imageTag)
		return "", ctx.Err()
	}

	// Stop old container
	if agent.ImageRef != "" {
		_ = b.containers.StopAgent(ctx, "airlock-agent-"+agentUUID.String()[:8])
	}

	// Start new container (dbPassword already decrypted above).
	schemaName := fmt.Sprintf("agent_%s", sanitizeUUID(agentID))
	agentToken, err := auth.IssueAgentToken(b.cfg.JWTSecret, agentUUID)
	if err != nil {
		completeBuild("failed", err.Error(), hash, imageTag)
		return "", fmt.Errorf("issue agent token: %w", err)
	}
	agentDBURL := b.agentDBURL(schemaName, dbPassword, schemaName)
	_, err = b.containers.StartAgent(ctx, container.AgentOpts{
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
		completeBuild("failed", err.Error(), hash, imageTag)
		return "", fmt.Errorf("start upgraded agent: %w", err)
	}

	// Update refs
	if err := q.UpdateAgentRefs(ctx, dbq.UpdateAgentRefsParams{
		ID:        agentPgUUID,
		SourceRef: hash,
		ImageRef:  imageTag,
	}); err != nil {
		return "", fmt.Errorf("update refs: %w", err)
	}

	completeBuild("complete", "", hash, imageTag)
	return solResult.ExitMessage, nil
}
