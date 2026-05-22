package builder

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/scaffold"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Execute is the single pipeline shared by Build, RunUpgrade, and
// Rollback. Each entry point constructs a BuildPlan and hands it off
// here; the differences between flows collapse into conditional phases
// keyed off plan.Kind / plan.Instruction / plan.StartCommit.
//
// Phases:
//
//	A.  Lock + per-flow setup (build creates the agent record + schema;
//	    upgrade/rollback acquire the upgrade lock and load the agent).
//	A4. Insert the agent_builds row so the "started" event carries its id.
//	B.  Reposition the repo if StartCommit is set (rollback only): save
//	    current HEAD as PreserveBranch, then git reset --hard.
//	C.  Codegen if Instruction is non-empty: run Sol on a working
//	    branch, commit, merge back.
//	D.  Build the docker image at current HEAD.
//	E.  Validate migrations on a schema clone — up→down→up for
//	    build/upgrade; the rollback-specific down-to dry run is wired in
//	    by Phase 4 of the plan and lives in a sibling helper.
//	F.  Swap the agent container (stop old if present, start new).
//	G/H. Update agents.{source_ref,image_ref,status} and complete the
//	    agent_builds row.
//
// Returns the agent-builder's exit-tool message (when Sol ran) so
// the caller can plumb it into the originating conversation. Empty
// string is fine when no Sol ran.
func (b *BuildService) Execute(ctx context.Context, plan BuildPlan) (string, error) {
	q := dbq.New(b.db.Pool())
	agent := plan.Agent
	agentID := uuidString(agent.ID)
	agentUUID := uuid.UUID(agent.ID.Bytes)
	repoPath := b.AgentRepoPath(agentID)

	// ── Phase A: per-flow setup ────────────────────────────────────────
	//
	// For initial builds we still need to create the per-agent repo,
	// scaffold, and provision the DB schema + role. Everything from
	// Phase A4 onward is identical across kinds.
	var dbPassword string
	var schemaName string
	var prepareErr error

	if plan.Kind == BuildKindBuild {
		dbPassword, schemaName, prepareErr = b.prepareNewAgent(ctx, q, agent, agentID)
		if prepareErr != nil {
			return "", prepareErr
		}
	} else {
		schemaName = fmt.Sprintf("agent_%s", sanitizeUUID(agentID))
		pw, err := b.encryptor.Get(ctx, "agent/"+agentID+"/db_password", agent.DbPassword)
		if err != nil {
			return "", fmt.Errorf("decrypt db password: %w", err)
		}
		dbPassword = pw
	}

	// ── Phase A4: agent_builds row ─────────────────────────────────────
	build, err := q.CreateAgentBuild(ctx, dbq.CreateAgentBuildParams{
		AgentID:          agent.ID,
		Type:             string(plan.Kind),
		Instructions:     plan.Instruction,
		RollbackTargetID: plan.RollbackTargetID,
	})
	if err != nil {
		return "", fmt.Errorf("create build record: %w", err)
	}
	buildUUID := uuid.UUID(build.ID.Bytes)
	b.events.PublishBuildEvent(ctx, agentUUID, buildUUID, "started", "")

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
	logLine := solLog

	completeBuild := func(status, errMsg, sourceRef, imageRef string) {
		// sdk_version records what the build was DEPLOYED with — that's
		// what rollback needs to detect drift. Stamp on success only; a
		// failed build never deployed anything.
		sdkVersion := ""
		if status == "complete" {
			sdkVersion = agentsdk.Version
		}
		_ = q.UpdateAgentBuildComplete(context.Background(), dbq.UpdateAgentBuildCompleteParams{
			ID:           build.ID,
			Status:       status,
			ErrorMessage: errMsg,
			SourceRef:    sourceRef,
			ImageRef:     imageRef,
			SdkVersion:   sdkVersion,
		})
		event := status
		if event == "complete" {
			// Build-event names mirror REST status values, with one
			// exception: success is "complete" on both sides. failed
			// and cancelled match.
		}
		b.events.PublishBuildEvent(context.Background(), agentUUID, buildUUID, event, errMsg)
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", "", "")
		return "", ctx.Err()
	}

	// ── Concurrency gate ───────────────────────────────────────────────
	//
	// One semaphore for every build that runs anywhere in airlock —
	// initial builds, manual upgrades, rollbacks, mass-rebuild fanout.
	// Sized at New() from runtime.NumCPU()/2 (or AIRLOCK_BUILD_PARALLELISM).
	// The agent_builds row already exists and shows status="building" —
	// from the operator's POV the build is queued; that's accurate
	// enough without inventing a new status. Cancellation while
	// queued is honored: ctx.Done() is the SAME context the cancel
	// button drives.
	select {
	case b.buildSem <- struct{}{}:
	case <-ctx.Done():
		completeBuild("cancelled", "cancelled while queued", "", "")
		return "", ctx.Err()
	}
	defer func() { <-b.buildSem }()

	// ── Phase B: reposition the repo (rollback only) ───────────────────
	if plan.StartCommit != "" {
		logLine(fmt.Sprintf("Repositioning repo to %s...", plan.StartCommit[:min(12, len(plan.StartCommit))]))
		if plan.PreserveBranch != "" {
			if err := SaveRef(repoPath, plan.PreserveBranch, "HEAD"); err != nil {
				completeBuild("failed", err.Error(), "", "")
				return "", fmt.Errorf("save preserve branch: %w", err)
			}
			logLine(fmt.Sprintf("Saved forward history at %s", plan.PreserveBranch))
		}
		if err := ResetHard(repoPath, plan.StartCommit); err != nil {
			completeBuild("failed", err.Error(), "", "")
			return "", fmt.Errorf("reset repo: %w", err)
		}
	}

	// ── Schema clone for codegen test DB + later validation ────────────
	//
	// Naming mirrors what the per-flow code used to pick. The build flow
	// produces an empty schema (just-provisioned source); upgrade and
	// rollback clone the live schema (which is at HEAD).
	var cloneName string
	switch plan.Kind {
	case BuildKindBuild:
		cloneName = fmt.Sprintf("agent_%s_test_%s", sanitizeUUID(agentID), randHex4())
	case BuildKindUpgrade, BuildKindRollback:
		cloneName = fmt.Sprintf("agent_%s_upgrade_%s", sanitizeUUID(agentID), sanitizeUUID(plan.RunID))
	}
	if err := b.cloneSchema(ctx, schemaName, cloneName, schemaName); err != nil {
		completeBuild("failed", err.Error(), "", "")
		return "", fmt.Errorf("clone schema: %w", err)
	}
	defer func() {
		if err := b.dropSchemaClone(context.Background(), cloneName); err != nil {
			b.logger.Warn("failed to drop clone schema", zap.Error(err))
		}
	}()

	testDBURL := b.agentDBURL(schemaName, dbPassword, cloneName)
	testDBPSQL := b.agentDBURLBase(b.cfg.DBHostAgent, schemaName, dbPassword)

	// ── Phase C: codegen (Sol) if Instruction is non-empty ─────────────
	commitHash, exitMessage, codegenErr := b.runCodegen(ctx, plan, agent, build, agentID, agentUUID, testDBURL, testDBPSQL, cloneName, solLog)
	if codegenErr != nil {
		// A "refused" exit is recorded distinctly: the request was out
		// of scope, the existing agent is untouched — not a build that
		// failed. Callers (RunUpgrade/Rollback) likewise unwrap
		// RefusedError to report a declined request, not a failure.
		buildStatus := "failed"
		var refErr *RefusedError
		if errors.As(codegenErr, &refErr) {
			buildStatus = "refused"
		}
		completeBuild(buildStatus, codegenErr.Error(), commitHash, "")
		return "", codegenErr
	}
	if commitHash == "" {
		// No codegen ran — current HEAD is the source ref. After Phase B
		// reset this is the target commit; without Phase B it's whatever
		// main pointed at coming in.
		hash, err := gitOutput(repoPath, "rev-parse", "HEAD")
		if err != nil {
			completeBuild("failed", err.Error(), "", "")
			return "", fmt.Errorf("rev-parse HEAD: %w", err)
		}
		commitHash = hash
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", commitHash, "")
		return "", ctx.Err()
	}

	// ── Phase D: build the image at current HEAD ───────────────────────
	logLine("Building Docker image...")
	contextDir := repoPath
	if err := scaffold.GenerateDockerfile(contextDir, scaffold.ScaffoldData{
		AgentID:         agentID,
		Module:          "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v" + agentsdk.Version,
		AgentBaseImage:  b.cfg.AgentBaseImage,
	}); err != nil {
		completeBuild("failed", err.Error(), commitHash, "")
		return "", fmt.Errorf("generate Dockerfile: %w", err)
	}
	// Bump the agent's go.mod require line to the current SDK version so
	// gopls/editor tooling shows what the build is actually linking
	// against (the replace directive shadows it for compilation). Skipped
	// on the very first build (scaffold already wrote the right version).
	if plan.Kind != BuildKindBuild {
		if err := bumpAgentSDKRequire(ctx, contextDir, agentsdk.Version); err != nil {
			completeBuild("failed", err.Error(), commitHash, "")
			return "", fmt.Errorf("bump agent SDK require: %w", err)
		}
	}
	imageTag, err := buildImage(ctx, b.cfg, agentID, contextDir, commitHash, dockerLog)
	if err != nil {
		// Bare rebuild (upgrade with no instructions and no source change)
		// against a newer SDK is the canonical case where compile breakage
		// surfaces. Steer the user to the codegen path.
		if plan.Kind == BuildKindUpgrade && plan.Instruction == "" {
			msg := fmt.Sprintf("rebuild failed to compile against the current agentsdk. "+
				"If the SDK API changed, re-run Upgrade with a short description so the "+
				"builder can adapt the code.\n\n%s", err.Error())
			completeBuild("failed", msg, commitHash, "")
			return "", errors.New(msg)
		}
		completeBuild("failed", err.Error(), commitHash, "")
		return "", fmt.Errorf("build image: %w", err)
	}
	b.logger.Info("image built", zap.String("image", imageTag))

	// ── Phase E: validate migrations on the clone ──────────────────────
	//
	// For build/upgrade we run the NEW image with AGENT_VALIDATE_MIGRATIONS=1
	// (up→down→up) — the canonical reversibility check.
	//
	// For rollback the new image's migrations are the SHORTER set (we're
	// going backwards), so up→down→up there would only re-verify what was
	// already verified when the target was originally built. The
	// interesting check is whether the CURRENT image (which has the
	// migrations being reversed) can goose-down-to the target version.
	// Same pre-flight envelope (run a one-shot container against a fresh
	// schema clone), different env var.
	if plan.Kind == BuildKindRollback {
		targetVersion, vErr := MigrationVersionAt(repoPath, plan.StartCommit)
		if vErr != nil {
			completeBuild("failed", vErr.Error(), commitHash, imageTag)
			return "", fmt.Errorf("read target migration version: %w", vErr)
		}
		if err := b.runDownToCheck(ctx, agent.ImageRef, testDBURL, targetVersion, logLine); err != nil {
			completeBuild("failed", err.Error(), commitHash, imageTag)
			return "", fmt.Errorf("rollback pre-flight: %w", err)
		}
		liveDBURL := b.agentDBURL(schemaName, dbPassword, schemaName)
		if err := b.runDownToCheck(ctx, agent.ImageRef, liveDBURL, targetVersion, logLine); err != nil {
			completeBuild("failed", err.Error(), commitHash, imageTag)
			return "", fmt.Errorf("rollback apply: %w", err)
		}
	} else {
		if err := b.validateMigrations(ctx, imageTag, testDBURL, logLine); err != nil {
			completeBuild("failed", err.Error(), commitHash, imageTag)
			return "", fmt.Errorf("migration validation: %w", err)
		}
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", commitHash, imageTag)
		return "", ctx.Err()
	}

	// ── Phase F: swap the container ────────────────────────────────────
	logLine("Starting agent container...")
	if agent.ImageRef != "" {
		_ = b.containers.StopAgent(ctx, "airlock-agent-"+agentUUID.String()[:8])
	}
	agentToken, err := auth.IssueAgentToken(b.cfg.JWTSecret, agentUUID)
	if err != nil {
		completeBuild("failed", err.Error(), commitHash, imageTag)
		return "", fmt.Errorf("issue agent token: %w", err)
	}
	agentDBURL := b.agentDBURL(schemaName, dbPassword, schemaName)
	if _, err := b.containers.StartAgent(ctx, container.AgentOpts{
		AgentID: agentUUID,
		Image:   imageTag,
		Env: map[string]string{
			"AIRLOCK_AGENT_ID":    agentID,
			"AIRLOCK_API_URL":     b.cfg.APIURLAgent,
			"AIRLOCK_DB_URL":      agentDBURL,
			"AIRLOCK_AGENT_TOKEN": agentToken,
		},
	}); err != nil {
		completeBuild("failed", err.Error(), commitHash, imageTag)
		return "", fmt.Errorf("start agent: %w", err)
	}

	// ── Phase G+H: update agent + complete build row ───────────────────
	if plan.Kind == BuildKindBuild {
		if err := q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{
			ID:     agent.ID,
			Status: "active",
		}); err != nil {
			return "", fmt.Errorf("update status to active: %w", err)
		}
	}
	if err := q.UpdateAgentRefs(ctx, dbq.UpdateAgentRefsParams{
		ID:        agent.ID,
		SourceRef: commitHash,
		ImageRef:  imageTag,
	}); err != nil {
		return "", fmt.Errorf("update refs: %w", err)
	}
	completeBuild("complete", "", commitHash, imageTag)

	if exitMessage == "" && plan.Kind == BuildKindUpgrade && plan.Instruction == "" {
		exitMessage = "Rebuilt against the current agentsdk (no code changes)."
	}
	return exitMessage, nil
}

// prepareNewAgent runs the build-only setup: initialize the per-agent
// repo, commit the scaffold, merge to main, provision the Postgres
// schema + role, encrypt and store the role password. Returns the
// plaintext password (re-used to mint container env URLs without going
// back through encryptor.Get) and the schema name.
func (b *BuildService) prepareNewAgent(ctx context.Context, q *dbq.Queries, agent dbq.Agent, agentID string) (string, string, error) {
	repoPath := b.AgentRepoPath(agentID)

	if err := InitAgentRepo(b.cfg.AgentReposPath, agentID); err != nil {
		return "", "", fmt.Errorf("init agent repo: %w", err)
	}

	data := scaffold.ScaffoldData{
		AgentID:         agentID,
		Module:          "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v" + agentsdk.Version,
		AgentBaseImage:  b.cfg.AgentBaseImage,
	}
	if _, err := CommitScaffold(repoPath, data); err != nil {
		return "", "", fmt.Errorf("commit scaffold: %w", err)
	}
	if err := MergeBranch(repoPath, "build/init"); err != nil {
		return "", "", fmt.Errorf("merge scaffold: %w", err)
	}

	schemaName := fmt.Sprintf("agent_%s", sanitizeUUID(agentID))
	pw, err := b.createAgentSchema(ctx, agentID, schemaName)
	if err != nil {
		return "", "", fmt.Errorf("create schema: %w", err)
	}
	enc, err := b.encryptor.Put(ctx, "agent/"+agentID+"/db_password", pw)
	if err != nil {
		return "", "", fmt.Errorf("encrypt db password: %w", err)
	}
	if err := q.UpdateAgentDBPassword(ctx, dbq.UpdateAgentDBPasswordParams{
		ID:         agent.ID,
		DbPassword: enc,
	}); err != nil {
		return "", "", fmt.Errorf("update agent db_password: %w", err)
	}
	return pw, schemaName, nil
}

// randHex4 returns 8 hex chars of entropy — used to disambiguate the
// build-time schema clone name when multiple builds for the same agent
// race (rare but possible during retries).
func randHex4() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure the imports cover everything we reference; pgtype is used
// indirectly via dbq params. Keeping it imported for clarity.
var _ pgtype.UUID
