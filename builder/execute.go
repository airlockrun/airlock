package builder

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/scaffold"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// buildPublisher implements buildSink: it streams structured codegen activity
// to the per-build WS topic and persists the todo snapshot. It also tracks the
// latest task counts so the lifecycle badge (on the agent topic) and the build
// row's completion event carry tasks_done/total. Its methods run on the
// runner's bus goroutine during runCodegen — sequential, never concurrent with
// the surrounding Execute flow — so the unsynchronized counter fields are safe.
type buildPublisher struct {
	events     EventPublisher
	q          *dbq.Queries
	agentUUID  uuid.UUID
	buildUUID  uuid.UUID
	buildID    pgtype.UUID
	bl         *buildLog
	tasksDone  int32
	tasksTotal int32
}

// ErrDeploymentConflict means another lifecycle operation changed the agent
// after this build observed its state. The caller must leave the live lifecycle
// status untouched.
var ErrDeploymentConflict = errors.New("agent deployment cancelled by a concurrent lifecycle change")

type deploymentQueries interface {
	IncrementAgentTokenVersion(context.Context, pgtype.UUID) (int64, error)
	FinalizeAgentDeployment(context.Context, dbq.FinalizeAgentDeploymentParams) (int64, error)
}

// deploymentAttemptError carries the token version reserved by Phase F so an
// initial build can mark itself failed without racing a later Stop rotation.
type deploymentAttemptError struct {
	err          error
	tokenVersion int64
}

func (e *deploymentAttemptError) Error() string { return e.err.Error() }
func (e *deploymentAttemptError) Unwrap() error { return e.err }

// OnTodos persists the todo snapshot, streams it on the per-build topic, and
// pushes the task progress onto the agent topic for the "Building N/M" badge.
func (bp *buildPublisher) OnTodos(todosJSON []byte, done, total int) {
	bp.tasksDone, bp.tasksTotal = int32(done), int32(total)
	_ = bp.q.UpdateAgentBuildTodos(context.Background(), dbq.UpdateAgentBuildTodosParams{
		ID:    bp.buildID,
		Todos: todosJSON,
	})
	bp.events.PublishBuildTodos(context.Background(), bp.buildUUID, bp.bl.nextSeq(), todosJSON)
	bp.events.PublishBuildEvent(context.Background(), bp.agentUUID, bp.buildUUID, "progress", "", "codegen", bp.tasksDone, bp.tasksTotal)
}

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
	agent := plan.Agent
	agentID := uuidString(agent.ID)
	agentUUID := uuid.UUID(agent.ID.Bytes)
	if agent.GitMode == "read_only" && plan.Instruction != "" {
		return "", errors.New("agent uses read-only Git; push source changes to the connected repository")
	}

	// Capacity is local to this build-worker replica. Acquire it before any
	// database connection or source lock so queued builds consume no shared
	// resources. The per-agent advisory lock below provides cross-replica
	// correctness once this worker has capacity to run the build.
	select {
	case b.buildSem <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-b.buildSem }()

	repoPath := b.AgentRepoPath(agentID)
	q := dbq.New(b.db.Pool())
	sourceLock, err := b.AcquireSourceLock(ctx, agentID)
	if err != nil {
		return "", err
	}
	defer sourceLock.Unlock()

	// Unwind any half-finished git state from a prior build that was
	// killed mid-operation (e.g. agent-builder container stopped between
	// `git add` and `git commit`). Without this the next build refuses
	// the "dirty" repo even though every staged file is airlock-owned.
	if recovered, err := RecoverAgentRepo(repoPath); err != nil {
		return "", fmt.Errorf("recover agent repo: %w", err)
	} else if recovered {
		b.logger.Warn("recovered half-finished git state in agent repo",
			zap.String("agent_id", agentID), zap.String("repo", repoPath))
	}

	// Dev: generate the local lib proxy once for this build — shared by
	// codegen's toolserver and the image build, both of which point GOPROXY
	// at it so agentsdk/goai/sol resolve from live source. Prod: empty dir,
	// builds resolve published versions from the public proxy.
	goProxyDir, proxyCleanup, err := b.ensureLibProxy()
	if err != nil {
		return "", fmt.Errorf("generate lib proxy: %w", err)
	}
	defer proxyCleanup()

	// The version the agent's go.mod pins for agentsdk and that the proxy
	// serves it at — content-addressed (v<const>-dev<hash>) in dev so live lib
	// edits resolve fresh, published v<const> in prod. Shared by housekeeping
	// and scaffold below so the agent's go.mod and the proxy always agree.
	sdkVer, err := b.agentSDKVersion()
	if err != nil {
		return "", fmt.Errorf("resolve agent sdk version: %w", err)
	}

	// ── Phase A: per-flow setup ────────────────────────────────────────
	//
	// For initial builds we still need to create the per-agent repo,
	// scaffold, and provision the DB schema + role. Everything from
	// Phase A4 onward is identical across kinds.
	var dbPassword string
	var schemaName string
	var prepareErr error

	if plan.Kind == BuildKindBuild {
		dbPassword, schemaName, prepareErr = b.prepareNewAgent(ctx, q, agent, agentID, plan.SkipScaffold)
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

		// Re-assert the role to the stored password before the build touches it
		// (migration validation connects as the role). Heals a role that drifted
		// from the stored copy or a recreated Postgres volume that lost the role
		// — idempotent, never rotates. Pairs with the SDK-bump mass rebuild so a
		// drifted agent recovers on its next upgrade rather than needing a manual
		// fix.
		if err := b.ensureAgentRole(ctx, schemaName, dbPassword); err != nil {
			return "", fmt.Errorf("provision agent db: %w", err)
		}
	}

	// ── Phase A4: agent_builds row ─────────────────────────────────────
	buildInstructions := plan.Instruction
	if plan.Message != "" {
		buildInstructions = plan.Message
	}
	build, err := q.CreateAgentBuild(ctx, dbq.CreateAgentBuildParams{
		AgentID:          agent.ID,
		Type:             string(plan.Kind),
		Instructions:     buildInstructions,
		RollbackTargetID: plan.RollbackTargetID,
	})
	if err != nil {
		return "", fmt.Errorf("create build record: %w", err)
	}
	buildUUID := uuid.UUID(build.ID.Bytes)
	b.events.PublishBuildEvent(ctx, agentUUID, buildUUID, "started", "", "codegen", 0, 0)

	bl := newBuildLog(q, build.ID, b.logger)
	defer bl.close()

	bp := &buildPublisher{
		events:    b.events,
		q:         q,
		agentUUID: agentUUID,
		buildUUID: buildUUID,
		buildID:   build.ID,
		bl:        bl,
	}

	solLog := func(line string) {
		seq := bl.appendSol(line)
		b.events.PublishBuildLogLine(ctx, agentUUID, buildUUID, seq, "sol", line)
	}
	dockerLog := func(line string) {
		seq := bl.appendDocker(line)
		b.events.PublishBuildLogLine(ctx, agentUUID, buildUUID, seq, "docker", line)
	}
	logLine := solLog

	// Make an imported-from-git build legible: the repo was cloned in before the
	// build (in the service, not this log), so without this the only git line
	// would be the misleading "Pushing to..." below.
	if plan.SkipScaffold && agent.GitRemoteUrl != "" {
		logLine(fmt.Sprintf("Imported existing code from %s (scaffold skipped).", agent.GitRemoteUrl))
	}

	// The agent's exit-tool outcome (set after codegen runs), persisted on
	// the build row and rendered as the "Result" alongside any infra error.
	var exitStatus, exitMessage string

	completeBuild := func(status, errMsg, failKind, sourceRef, imageRef string) {
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
			ExitStatus:   exitStatus,
			ExitMessage:  exitMessage,
			FailureKind:  failKind,
		})
		b.events.PublishBuildEvent(context.Background(), agentUUID, buildUUID, status, errMsg, "", bp.tasksDone, bp.tasksTotal)
	}

	// Failure classification. A failed build is either code-attributable
	// (compile error, migration reversibility, the agent's own exit-tool
	// error) or a platform failure (toolserver/docker/schema/git/deploy).
	// Only "code" failures feed the next upgrade's codegen diagnostics — an
	// agent can't fix a stale toolserver image. failInfra is the default for
	// every pipeline-mechanics failure; failCode marks the three cases the
	// agent should see.
	failInfra := func(err error, sourceRef, imageRef string) {
		completeBuild("failed", err.Error(), "infra", sourceRef, imageRef)
	}
	failCode := func(errMsg, sourceRef, imageRef string) {
		completeBuild("failed", errMsg, "code", sourceRef, imageRef)
	}

	// publishPhase emits a lightweight badge update on the agent topic as the
	// pipeline moves past codegen (image build → migrations → deploy), so the
	// badge stops freezing on the final N/M task count.
	publishPhase := func(phase string) {
		b.events.PublishBuildEvent(ctx, agentUUID, buildUUID, "progress", "", phase, bp.tasksDone, bp.tasksTotal)
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", "", "", "")
		return "", ctx.Err()
	}

	// ── Phase B: reposition the repo (rollback only) ───────────────────
	if plan.StartCommit != "" {
		logLine(fmt.Sprintf("Repositioning repo to %s...", plan.StartCommit[:min(12, len(plan.StartCommit))]))
		if plan.PreserveBranch != "" {
			if err := SaveRef(repoPath, plan.PreserveBranch, "HEAD"); err != nil {
				failInfra(err, "", "")
				return "", fmt.Errorf("save preserve branch: %w", err)
			}
			logLine(fmt.Sprintf("Saved forward history at %s", plan.PreserveBranch))
		}
		if err := ResetHard(repoPath, plan.StartCommit); err != nil {
			failInfra(err, "", "")
			return "", fmt.Errorf("reset repo: %w", err)
		}
	}

	// ── Phase B2: airlock housekeeping ─────────────────────────────────
	//
	// Regenerate airlock-managed files (Dockerfile from scaffold template,
	// .gitignore required entries, go.mod require lines for agentsdk/
	// goai/sol) so the agent repo carries airlock's current canonical
	// state before Sol clones it for codegen. Idempotent: a no-op for an
	// already-current repo. Commits ONCE if anything changed, so the
	// chore lands on top of any Phase B rollback reset and is visible to
	// Sol's workdir clone in Phase C. Skipped for BuildKindBuild because
	// prepareNewAgent's scaffold already wrote canonical state.
	if plan.Kind != BuildKindBuild && agent.GitMode != "read_only" {
		hk, err := runHousekeeping(ctx, repoPath, scaffold.ScaffoldData{
			AgentID:         agentID,
			GoVersion:       buildGoVersion,
			AgentSDKVersion: sdkVer,
			AgentBaseImage:  b.cfg.AgentBaseImage,
		})
		if err != nil {
			failInfra(err, "", "")
			return "", fmt.Errorf("housekeeping: %w", err)
		}
		if hk.Changed() {
			if err := commitHousekeeping(repoPath, hk); err != nil {
				failInfra(err, "", "")
				return "", fmt.Errorf("commit housekeeping: %w", err)
			}
			logLine("Airlock housekeeping: refreshed managed files (Dockerfile/.gitignore/go.mod)")
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
		failInfra(err, "", "")
		return "", fmt.Errorf("clone schema: %w", err)
	}
	defer func() {
		if err := b.dropSchemaClone(context.Background(), cloneName); err != nil {
			b.logger.Warn("failed to drop clone schema", zap.Error(err))
		}
	}()

	testDBURL := b.agentDBURL(schemaName, dbPassword, cloneName)
	testDBPSQL := b.agentDBURLBase(b.cfg.DBHostAgent, b.cfg.DBPortAgent, schemaName, dbPassword)

	// ── Phase C: codegen (Sol) if Instruction is non-empty ─────────────
	commitHash, exitStatus, exitMessage, codegenErr := b.runCodegen(ctx, plan, agent, build, agentID, agentUUID, testDBURL, testDBPSQL, cloneName, goProxyDir, solLog, dockerLog, bp)
	if codegenErr != nil {
		// User cancelled mid-codegen: record it as cancelled (not failed) so
		// the lifecycle event clears the "building" badge and the row reads
		// honestly.
		if errors.Is(codegenErr, context.Canceled) {
			completeBuild("cancelled", "cancelled by user", "", commitHash, "")
			return "", codegenErr
		}
		// A "refused" exit is recorded distinctly: the request was out
		// of scope, the existing agent is untouched — not a build that
		// failed. Callers (RunUpgrade/Rollback) likewise unwrap
		// RefusedError to report a declined request, not a failure.
		buildStatus := "failed"
		failKind := "infra"
		var refErr *RefusedError
		var verificationErr *codegenVerificationError
		if errors.As(codegenErr, &refErr) {
			buildStatus = "refused"
			failKind = ""
		} else if errors.As(codegenErr, &verificationErr) {
			failKind = "code"
		} else if exitStatus == exitStatusError {
			// The agent ran and reported its own failure via the exit tool —
			// code-domain; the next upgrade's codegen should see it.
			failKind = "code"
		} else if exitStatus == "" {
			// Not the agent's own exit (toolserver/runner/connect fault) — a
			// platform failure. Surface it in the log; don't feed it back to
			// the agent (it can't fix the platform). The exit-status paths
			// already logged their own [exit] line in runCodegen.
			solLog("[error] " + codegenErr.Error())
		}
		completeBuild(buildStatus, codegenErr.Error(), failKind, commitHash, "")
		return "", codegenErr
	}
	if commitHash == "" {
		// No codegen ran — current HEAD is the source ref. After Phase B
		// reset this is the target commit; without Phase B it's whatever
		// main pointed at coming in.
		hash, err := gitOutput(repoPath, "rev-parse", "HEAD")
		if err != nil {
			failInfra(err, "", "")
			return "", fmt.Errorf("rev-parse HEAD: %w", err)
		}
		commitHash = hash
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", "", commitHash, "")
		return "", ctx.Err()
	}

	// ── Phase C2: push codegen commits back to the external remote ─────
	//
	// Optional — only for agents with a connected remote. Happens BEFORE
	// the image build so a rebase conflict fails fast without burning
	// docker build time. A conflict preserves the codegen commit on a
	// side branch (airlock/upgrade/{runID}) on the remote and resets
	// main locally, so the agent stays on its previous image.
	if agent.GitRemoteUrl != "" && agent.GitMode != "read_only" {
		// An imported/cloned repo is already in sync with the remote, so this
		// push is a fast-forward no-op — say "Syncing" rather than "Pushing" so
		// it doesn't read like the agent is overwriting the remote.
		if plan.SkipScaffold {
			logLine(fmt.Sprintf("Syncing with %s...", agent.GitRemoteUrl))
		} else {
			logLine(fmt.Sprintf("Pushing to %s...", agent.GitRemoteUrl))
		}
		pushErr := b.pushAgentRepo(ctx, agent, plan.RunID)
		switch {
		case pushErr == nil:
			if uerr := q.UpdateAgentGitLastSyncedRef(ctx, dbq.UpdateAgentGitLastSyncedRefParams{
				ID:               agent.ID,
				GitLastSyncedRef: commitHash,
			}); uerr != nil {
				b.logger.Warn("update git_last_synced_ref", zap.Error(uerr))
			}
		case errors.As(pushErr, new(*PushConflictError)):
			// Content conflict — the codegen commit is preserved on a
			// side branch on the remote and main is reset locally. The
			// user needs to know, so fail the build rather than silently
			// keep going. pushAgentRepo already surfaces the side-branch
			// name in the error message.
			failInfra(pushErr, commitHash, "")
			return "", pushErr
		default:
			failInfra(pushErr, commitHash, "")
			return "", pushErr
		}
	}

	// ── Phase D: build the image at current HEAD ───────────────────────
	//
	// Deploy invariant: the per-agent repo's `main` and the agent's deployed
	// `image_ref` are intentionally decoupled. Codegen already committed +
	// merged to `main` in Phase C, so an unbuildable commit can land there —
	// but the container swap (Phase F) and the `image_ref`/`source_ref` write
	// (Phase G) run ONLY after this build and migration validation (Phase E)
	// pass. Every failure below fails the build (failCode for compile/migration,
	// failInfra otherwise) and returns without deploying, so the agent stays on
	// its last buildable image. A
	// broken `main` is expected (iterate on top, or rollback→upgrade); it is
	// never deployed.
	publishPhase("image")
	logLine("Building Docker image...")
	contextDir := repoPath
	// Regenerate the Dockerfile into a TEMP directory (not contextDir)
	// so airlock's current template is used without overwriting the
	// user-committed Dockerfile sitting in the agent repo. `docker
	// build -f` points the build at our generated copy while keeping
	// contextDir as the build context.
	dockerfileDir, err := os.MkdirTemp("", "airlock-dockerfile-*")
	if err != nil {
		failInfra(err, commitHash, "")
		return "", fmt.Errorf("create dockerfile temp dir: %w", err)
	}
	defer os.RemoveAll(dockerfileDir)
	if err := scaffold.GenerateDockerfile(dockerfileDir, scaffold.ScaffoldData{
		AgentID:         agentID,
		GoVersion:       buildGoVersion,
		AgentSDKVersion: sdkVer,
		AgentBaseImage:  b.cfg.AgentBaseImage,
	}); err != nil {
		failInfra(err, commitHash, "")
		return "", fmt.Errorf("generate Dockerfile: %w", err)
	}
	imageTag, err := buildImage(ctx, b.cfg, agentID, contextDir, commitHash, filepath.Join(dockerfileDir, "Dockerfile"), goProxyDir, dockerLog)
	if err != nil {
		// Bare rebuild (upgrade with no instructions and no source change)
		// against a newer SDK is the canonical case where compile breakage
		// surfaces. Steer the user to the codegen path.
		if plan.Kind == BuildKindUpgrade && plan.Instruction == "" {
			msg := fmt.Sprintf("rebuild failed to compile against the current agentsdk. "+
				"If the SDK API changed, re-run Upgrade with a short description so the "+
				"builder can adapt the code.\n\n%s", err.Error())
			failCode(msg, commitHash, "")
			return "", errors.New(msg)
		}
		failCode(err.Error(), commitHash, "")
		return "", fmt.Errorf("build image: %w", err)
	}
	b.logger.Info("image built", zap.String("image", imageTag))

	// ── Phase E: validate migrations on the clone ──────────────────────
	publishPhase("migrations")
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
			failInfra(vErr, commitHash, imageTag)
			return "", fmt.Errorf("read target migration version: %w", vErr)
		}
		if err := b.runDownToCheck(ctx, agent.ImageRef, testDBURL, targetVersion, logLine); err != nil {
			failCode(err.Error(), commitHash, imageTag)
			return "", fmt.Errorf("rollback pre-flight: %w", err)
		}
		liveDBURL := b.agentDBURL(schemaName, dbPassword, schemaName)
		if err := b.runDownToCheck(ctx, agent.ImageRef, liveDBURL, targetVersion, logLine); err != nil {
			failCode(err.Error(), commitHash, imageTag)
			return "", fmt.Errorf("rollback apply: %w", err)
		}
	} else {
		if err := b.validateMigrations(ctx, imageTag, testDBURL, logLine); err != nil {
			failCode(err.Error(), commitHash, imageTag)
			return "", fmt.Errorf("migration validation: %w", err)
		}
	}

	if ctx.Err() != nil {
		completeBuild("cancelled", "cancelled by user", "", commitHash, imageTag)
		return "", ctx.Err()
	}

	// ── Phase F: swap the container ────────────────────────────────────
	// The stop → start → FinalizeAgentDeployment sequence is the only window
	// where the running container can disagree with agents.image_ref.
	// LockSwap serialises this with EnsureRunning so a concurrent
	// trigger can't slip in and start the OLD image while we're
	// mid-swap (and vice versa). Held only for the swap itself —
	// codegen, image build, and migration validation already ran
	// without the lock above.
	publishPhase("deploy")
	logLine("Deploying agent image...")
	agentDBURL := b.agentDBURL(schemaName, dbPassword, schemaName)
	if err := b.deployAgent(ctx, q, plan, agentDBURL, commitHash, imageTag); err != nil {
		if errors.Is(err, ErrDeploymentConflict) {
			completeBuild("cancelled", err.Error(), "", commitHash, imageTag)
		} else {
			failInfra(err, commitHash, imageTag)
		}
		return "", err
	}

	// ── Phase G+H: complete build row ──────────────────────────────────
	completeBuild("complete", "", "", commitHash, imageTag)

	if exitMessage == "" && plan.Kind == BuildKindUpgrade && plan.Instruction == "" {
		exitMessage = "Rebuilt against the current agentsdk (no code changes)."
	}
	return exitMessage, nil
}

func (b *BuildService) deployAgent(ctx context.Context, q deploymentQueries, plan BuildPlan, agentDBURL, sourceRef, imageRef string) error {
	agent := plan.Agent
	agentID := uuidString(agent.ID)
	agentUUID := uuid.UUID(agent.ID.Bytes)
	expectedStatus := agent.Status
	nextStatus := agent.Status
	startContainer := true

	switch plan.Kind {
	case BuildKindBuild:
		expectedStatus = "building"
		nextStatus = "active"
	case BuildKindUpgrade, BuildKindRollback:
		switch agent.Status {
		case "active":
		case "failed":
			nextStatus = "active"
		case "stopped":
			startContainer = false
		default:
			return fmt.Errorf("%w: cannot deploy %s agent from status %q", ErrDeploymentConflict, plan.Kind, agent.Status)
		}
	default:
		return fmt.Errorf("unknown build kind %q", plan.Kind)
	}

	unlockSwap := b.containers.LockSwap(agentUUID)
	defer unlockSwap()

	tokenVersion, err := q.IncrementAgentTokenVersion(ctx, agent.ID)
	if err != nil {
		return fmt.Errorf("rotate agent token: %w", err)
	}
	attemptErr := func(err error) error {
		return &deploymentAttemptError{err: err, tokenVersion: tokenVersion}
	}

	if startContainer {
		if agent.ImageRef != "" {
			_ = b.containers.StopAgent(ctx, agentUUID)
		}
		agentToken, err := auth.IssueAgentToken(b.cfg.JWTSecret, agentUUID, tokenVersion)
		if err != nil {
			return attemptErr(fmt.Errorf("issue agent token: %w", err))
		}
		if _, err := b.containers.StartAgent(ctx, container.AgentOpts{
			AgentID: agentUUID,
			Image:   imageRef,
			Token:   agentToken,
			Env: map[string]string{
				"AIRLOCK_AGENT_ID": agentID,
				"AIRLOCK_API_URL":  b.cfg.APIURLAgent,
				"AIRLOCK_DB_URL":   agentDBURL,
			},
		}); err != nil {
			return attemptErr(fmt.Errorf("start agent: %w", err))
		}
	}

	rows, err := q.FinalizeAgentDeployment(ctx, dbq.FinalizeAgentDeploymentParams{
		ID:                agent.ID,
		SourceRef:         sourceRef,
		ImageRef:          imageRef,
		NextStatus:        nextStatus,
		AgentTokenVersion: tokenVersion,
		ExpectedStatus:    expectedStatus,
	})
	if err == nil && rows == 1 {
		return nil
	}

	var stopErr error
	if startContainer {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		stopErr = b.containers.StopAgent(stopCtx, agentUUID)
	}
	if err != nil {
		if stopErr != nil {
			err = errors.Join(err, fmt.Errorf("stop rejected deployment: %w", stopErr))
		}
		return attemptErr(fmt.Errorf("finalize agent deployment: %w", err))
	}
	conflictErr := error(ErrDeploymentConflict)
	if stopErr != nil {
		conflictErr = errors.Join(conflictErr, fmt.Errorf("stop rejected deployment: %w", stopErr))
	}
	return attemptErr(conflictErr)
}

// prepareNewAgent runs the build-only setup: initialize the per-agent
// repo, commit the scaffold, merge to main, provision the Postgres
// schema + role, encrypt and store the role password. Returns the
// plaintext password (re-used to mint container env URLs without going
// back through encryptor.Get) and the schema name.
func (b *BuildService) prepareNewAgent(ctx context.Context, q *dbq.Queries, agent dbq.Agent, agentID string, skipScaffold bool) (string, string, error) {
	repoPath := b.AgentRepoPath(agentID)

	if err := InitAgentRepo(b.cfg.AgentReposPath, agentID); err != nil {
		return "", "", fmt.Errorf("init agent repo: %w", err)
	}

	// A clone's repo is copied in already-complete (scaffold + the source
	// agent's customizations, all committed). Re-running the scaffold here
	// would overwrite scaffold-managed files (viewmodel.go, main.go,
	// index.templ, …) back to their defaults and — with no codegen to
	// regenerate the customizations — break the build. So skip it for clones;
	// the DB provisioning below still runs (the clone gets a fresh schema).
	if !skipScaffold {
		sdkVer, err := b.agentSDKVersion()
		if err != nil {
			return "", "", fmt.Errorf("resolve agent sdk version: %w", err)
		}
		data := scaffold.ScaffoldData{
			AgentID:         agentID,
			GoVersion:       buildGoVersion,
			AgentSDKVersion: sdkVer,
			AgentBaseImage:  b.cfg.AgentBaseImage,
		}
		if _, err := CommitScaffold(repoPath, data); err != nil {
			return "", "", fmt.Errorf("commit scaffold: %w", err)
		}
		if err := MergeBranch(repoPath, "build/init"); err != nil {
			return "", "", fmt.Errorf("merge scaffold: %w", err)
		}
		// A re-build of an agent whose earlier build failed reuses the existing
		// repo dir; clear any files a prior build/codegen left untracked so they
		// don't survive into the docker build context (which is the working tree)
		// and break the compile against the fresh scaffold.
		if err := CleanWorktree(repoPath); err != nil {
			return "", "", fmt.Errorf("clean worktree: %w", err)
		}
	}

	schemaName := fmt.Sprintf("agent_%s", sanitizeUUID(agentID))

	// Reuse the agent's existing DB password on a rebuild; mint a new one only
	// on first creation. Regenerating per build ALTERs the live role's
	// password, which races with in-flight containers/health checks (pq 28P01)
	// and risks permanent role↔stored drift if a build crashes mid-rotation.
	var pw string
	if agent.DbPassword != "" {
		stored, err := b.encryptor.Get(ctx, "agent/"+agentID+"/db_password", agent.DbPassword)
		if err != nil {
			return "", "", fmt.Errorf("decrypt db password: %w", err)
		}
		pw = stored
	} else {
		fresh, err := newDBPassword()
		if err != nil {
			return "", "", err
		}
		enc, err := b.encryptor.Put(ctx, "agent/"+agentID+"/db_password", fresh)
		if err != nil {
			return "", "", fmt.Errorf("encrypt db password: %w", err)
		}
		if err := q.UpdateAgentDBPassword(ctx, dbq.UpdateAgentDBPasswordParams{
			ID:         agent.ID,
			DbPassword: enc,
		}); err != nil {
			return "", "", fmt.Errorf("update agent db_password: %w", err)
		}
		pw = fresh
	}

	// Idempotently ensure the role (with this exact password) and schema exist
	// — never rotates, so rebuilds don't invalidate a running container's creds.
	if err := b.ensureAgentRole(ctx, schemaName, pw); err != nil {
		return "", "", fmt.Errorf("provision agent db: %w", err)
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
