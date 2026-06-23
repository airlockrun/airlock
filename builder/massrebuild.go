package builder

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RebuildAllOnSDKChange checks whether the airlock-bundled agentsdk
// version differs from the last-seen value persisted in
// system_settings, and if so kicks off a bounded-concurrency rebuild
// of every active/stopped agent. Designed to run once at airlock
// startup, after migrations have applied — the comparison itself is
// cheap, the rebuild only happens on actual drift.
//
// On success (image rebuilt, container restarted, migrations validated),
// the agent's existing status is preserved. On failure, the agent is
// transitioned to status=stopped with the build error captured in
// error_message — the operator decides whether to roll back, run an
// upgrade-with-description (Sol bridges the SDK gap), or investigate.
//
// last_seen_sdk_version is updated only AFTER every agent has been
// processed (regardless of individual successes) so a crash mid-batch
// re-triggers the same rebuild next boot. This is safe: a successful
// rebuild is idempotent (same source_ref → same image hash → image
// build cache hit → near-instant), and unchanged agents short-circuit
// in Execute's image-build phase.
func (b *BuildService) RebuildAllOnSDKChange(ctx context.Context) {
	q := dbq.New(b.db.Pool())
	settings, err := q.GetSystemSettings(ctx)
	if err != nil {
		b.logger.Error("mass-rebuild: load system settings", zap.Error(err))
		return
	}
	current := agentsdk.Version
	if settings.LastSeenSdkVersion == current {
		return
	}

	agents, err := q.ListRebuildableAgents(ctx)
	if err != nil {
		b.logger.Error("mass-rebuild: list agents", zap.Error(err))
		return
	}
	b.logger.Info("mass-rebuild: SDK changed",
		zap.String("from", settings.LastSeenSdkVersion),
		zap.String("to", current),
		zap.Int("agents", len(agents)))

	if len(agents) == 0 {
		if err := q.UpdateLastSeenSDKVersion(ctx, current); err != nil {
			b.logger.Error("mass-rebuild: stamp last_seen", zap.Error(err))
		}
		return
	}

	// No local pool — Execute's shared buildSem caps concurrency across
	// the whole service. Fanning out one goroutine per agent here just
	// lines them up behind that semaphore; the limit is enforced once,
	// centrally, and a manually-triggered upgrade landing mid-rebuild
	// queues fairly with the rest.
	b.logger.Info("mass-rebuild: starting")
	var wg sync.WaitGroup
	for _, agent := range agents {
		wg.Add(1)
		go func(a dbq.Agent) {
			defer wg.Done()
			b.rebuildOneAgent(a)
		}(agent)
	}
	wg.Wait()

	if err := q.UpdateLastSeenSDKVersion(context.Background(), current); err != nil {
		b.logger.Error("mass-rebuild: stamp last_seen", zap.Error(err))
		return
	}
	b.logger.Info("mass-rebuild: complete", zap.String("sdk", current))
}

// rebuildOneAgent runs the rebuild pipeline for a single agent inside
// the mass-rebuild loop. Acquires the upgrade lock the same way a
// regular Upgrade does so a manual operation can't race; on failure,
// transitions agents.status→stopped and stops any live container so
// the agent is in a known parked state (not silently serving stale
// code that may be incompatible with the new airlock).
func (b *BuildService) rebuildOneAgent(agent dbq.Agent) {
	agentID := uuidString(agent.ID)
	agentUUID := uuid.UUID(agent.ID.Bytes)
	dbCtx := context.Background()
	q := dbq.New(b.db.Pool())

	if err := b.AcquireUpgradeLock(dbCtx, agentID); err != nil {
		b.logger.Warn("mass-rebuild: skip (lock unavailable)",
			zap.String("agent_id", agentID), zap.Error(err))
		return
	}

	ctx, cancel := b.startBuild(agentID)
	defer cancel()
	defer b.finishBuild(agentID)

	plan := BuildPlan{
		Agent:       agent,
		Kind:        BuildKindUpgrade,
		Instruction: "",
		Reason:      "sdk_bump",
		RunID:       uuid.New().String(),
	}
	if _, err := b.Execute(ctx, plan); err != nil {
		b.logger.Error("mass-rebuild: agent failed",
			zap.String("agent_id", agentID), zap.Error(err))
		// Park the agent: stop the running container (if any) and flip
		// status=stopped with the error preserved. The Upgrade flow
		// would normally leave the old image running on failure; here
		// we want the operator's attention, so the agent goes offline
		// until they explicitly act.
		_ = b.containers.StopAgent(dbCtx, agentUUID)
		_ = q.UpdateAgentStatus(dbCtx, dbq.UpdateAgentStatusParams{
			ID:           agent.ID,
			Status:       "stopped",
			ErrorMessage: "rebuild against airlock " + agentsdk.Version + " failed: " + err.Error(),
		})
		_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
			ID:            agent.ID,
			UpgradeStatus: "failed",
			ErrorMessage:  err.Error(),
		})
		return
	}
	_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
		ID:            agent.ID,
		UpgradeStatus: "idle",
	})
	b.logger.Info("mass-rebuild: agent ok", zap.String("agent_id", agentID))
}

// buildParallelism caps how many builds run concurrently across the
// whole service — initial builds, manual upgrades, rollbacks, and the
// SDK-bump mass rebuild all share the same pool. Each build forks a
// docker build that's CPU + RAM heavy (Go compilation peaks around
// 1-2 GiB); concurrency too high will swap or OOM the host. Default:
// half the cores, at least 1. Operator override: AIRLOCK_BUILD_PARALLELISM.
func buildParallelism() int {
	if s := envInt("AIRLOCK_BUILD_PARALLELISM"); s > 0 {
		return s
	}
	n := runtime.NumCPU() / 2
	if n < 1 {
		n = 1
	}
	return n
}

func envInt(name string) int {
	v := os.Getenv(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
