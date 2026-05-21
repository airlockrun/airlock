package builder

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// RollbackInput describes a rollback request: the agent whose state we
// want to move backwards, and the agent_builds row that defines the
// target (its source_ref becomes main; its image_ref is rebuilt).
//
// ConversationID is optional — when set, the post-rollback notifier
// posts a single message describing the outcome, mirroring how upgrade
// closes the loop with the user.
type RollbackInput struct {
	AgentID        string
	BuildID        string
	ConversationID string
}

// Rollback reverses an agent to a previous build's source_ref. Wraps
// Execute the same way RunUpgrade does — the rollback-specific work
// (loading the target build, deciding whether an SDK gap needs Sol,
// recording the pre-rollback branch name) all happens here before the
// plan is handed to Execute; Execute itself doesn't know about
// rollback semantics beyond Phase B (reposition repo) and the
// rollback_target_id on the new agent_builds row.
//
// Synchronous; caller runs in a goroutine. Caller is responsible for
// AcquireUpgradeLock before calling — same gate as RunUpgrade so
// concurrent upgrades and rollbacks can't race.
func (b *BuildService) Rollback(_ context.Context, in RollbackInput) {
	ctx, cancel := b.startBuild(in.AgentID)
	defer cancel()
	defer b.finishBuild(in.AgentID)

	runID := uuid.New().String()

	b.logger.Info("rollback started",
		zap.String("agent_id", in.AgentID),
		zap.String("build_id", in.BuildID),
		zap.String("run_id", runID))

	q := dbq.New(b.db.Pool())
	agentPgUUID := mustParseUUID(in.AgentID)
	agentUUID, _ := uuid.Parse(in.AgentID)
	dbCtx := context.Background()

	agent, err := q.GetAgentByID(ctx, agentPgUUID)
	if err != nil {
		b.logger.Error("load agent for rollback", zap.Error(err))
		_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
			ID:            agentPgUUID,
			UpgradeStatus: "failed",
			ErrorMessage:  err.Error(),
		})
		return
	}

	targetID := mustParseUUID(in.BuildID)
	target, err := q.GetAgentBuild(ctx, targetID)
	if err != nil {
		b.failRollback(dbCtx, agentPgUUID, agentUUID, in.ConversationID, fmt.Errorf("load target build: %w", err))
		return
	}
	if uuid.UUID(target.AgentID.Bytes) != agentUUID {
		b.failRollback(dbCtx, agentPgUUID, agentUUID, in.ConversationID, errors.New("target build does not belong to this agent"))
		return
	}
	if target.Status != "complete" {
		b.failRollback(dbCtx, agentPgUUID, agentUUID, in.ConversationID, errors.New("can only roll back to a completed build"))
		return
	}
	if target.SourceRef == "" {
		b.failRollback(dbCtx, agentPgUUID, agentUUID, in.ConversationID, errors.New("target build has no source_ref"))
		return
	}
	if target.SourceRef == agent.SourceRef {
		b.failRollback(dbCtx, agentPgUUID, agentUUID, in.ConversationID, errors.New("target build is the current build"))
		return
	}

	// SDK gap → Sol migrates the rolled-back code forward to the current
	// SDK; matching SDKs → pure rollback (no codegen). The Sol prompt is
	// stable text we control, not user input, so it's safe to surface
	// as agent_builds.instructions for the UI.
	instruction := ""
	if target.SdkVersion != agent.SdkVersion && agent.SdkVersion != "" && target.SdkVersion != "" {
		instruction = fmt.Sprintf(
			"Migrate this code from agentsdk %s to %s. Preserve all existing functionality.",
			target.SdkVersion, agent.SdkVersion)
	}

	plan := BuildPlan{
		Agent:            agent,
		Kind:             BuildKindRollback,
		StartCommit:      target.SourceRef,
		PreserveBranch:   fmt.Sprintf("pre-rollback/%s", time.Now().UTC().Format("20060102-150405")),
		Instruction:      instruction,
		RollbackTargetID: pgtype.UUID{Bytes: target.ID.Bytes, Valid: true},
		Reason:           "rollback",
		RunID:            runID,
		ConversationID:   in.ConversationID,
	}

	successMsg, runErr := b.Execute(ctx, plan)
	if runErr != nil {
		b.failRollback(dbCtx, agentPgUUID, agentUUID, in.ConversationID, runErr)
		return
	}

	b.logger.Info("rollback completed", zap.String("agent_id", in.AgentID))
	_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
		ID:            agentPgUUID,
		UpgradeStatus: "idle",
		ErrorMessage:  "",
	})

	if in.ConversationID != "" && b.upgradeNotifier != nil {
		msg := successMsg
		if msg == "" {
			msg = fmt.Sprintf("Rolled back to build %s.", target.SourceRef[:min(12, len(target.SourceRef))])
		}
		if err := b.upgradeNotifier.NotifyUpgradeComplete(dbCtx, agentUUID, in.ConversationID, "success", msg); err != nil {
			b.logger.Error("post-rollback notification failed", zap.Error(err))
		}
	}
}

func (b *BuildService) failRollback(dbCtx context.Context, agentPgUUID pgtype.UUID, agentUUID uuid.UUID, conversationID string, runErr error) {
	q := dbq.New(b.db.Pool())
	errMsg := runErr.Error()
	if errors.Is(runErr, context.Canceled) {
		errMsg = "cancelled by user"
		b.logger.Info("rollback cancelled", zap.String("agent_id", agentUUID.String()))
	} else {
		b.logger.Error("rollback failed", zap.String("agent_id", agentUUID.String()), zap.Error(runErr))
	}
	_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
		ID:            agentPgUUID,
		UpgradeStatus: "failed",
		ErrorMessage:  errMsg,
	})
	if !errors.Is(runErr, context.Canceled) && conversationID != "" && b.upgradeNotifier != nil {
		if nerr := b.upgradeNotifier.NotifyUpgradeComplete(dbCtx, agentUUID, conversationID, "error", errMsg); nerr != nil {
			b.logger.Error("post-rollback error notification failed", zap.Error(nerr))
		}
	}
}
