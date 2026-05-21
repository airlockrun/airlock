package builder

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/airlockrun/airlock/db/dbq"
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
	Logs           string // captured log lines from the failed run (auto_fix)
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

// RunUpgrade executes the upgrade pipeline for an agent whose
// upgrade_status was set to "building" via AcquireUpgradeLock. Thin
// wrapper over Execute that handles the upgrade-specific outer
// lifecycle: route Execute's outcome into agents.upgrade_status and
// post the single conversation message describing the result.
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
	dbCtx := context.Background()

	agent, err := q.GetAgentByID(ctx, agentPgUUID)
	if err != nil {
		b.logger.Error("load agent for upgrade", zap.Error(err))
		_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
			ID:            agentPgUUID,
			UpgradeStatus: "failed",
			ErrorMessage:  err.Error(),
		})
		return
	}

	plan := BuildPlan{
		Agent:          agent,
		Kind:           BuildKindUpgrade,
		Instruction:    strings.TrimSpace(input.Description),
		Reason:         input.Reason,
		RunID:          input.RunID,
		ConversationID: input.ConversationID,
		Diagnostics:    autoFixContextFromInput(input),
	}

	successMsg, runErr := b.Execute(ctx, plan)
	if runErr != nil {
		errMsg := runErr.Error()
		if errors.Is(runErr, context.Canceled) {
			errMsg = "cancelled by user"
			b.logger.Info("upgrade cancelled", zap.String("agent_id", input.AgentID))
		} else {
			b.logger.Error("upgrade failed", zap.String("agent_id", input.AgentID), zap.Error(runErr))
		}
		_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
			ID:            agentPgUUID,
			UpgradeStatus: "failed",
			ErrorMessage:  errMsg,
		})
		// Surface the failure as a single conversation message — without
		// it the user only sees "still spinning" then nothing.
		// Cancellation skips the notification (the toast already covered it).
		if !errors.Is(runErr, context.Canceled) && input.ConversationID != "" && b.upgradeNotifier != nil {
			if nerr := b.upgradeNotifier.NotifyUpgradeComplete(dbCtx, agentUUID, input.ConversationID, "error", errMsg); nerr != nil {
				b.logger.Error("post-upgrade error notification failed", zap.Error(nerr))
			}
		}
		return
	}

	b.logger.Info("upgrade completed", zap.String("agent_id", input.AgentID))
	_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
		ID:            agentPgUUID,
		UpgradeStatus: "idle",
		ErrorMessage:  "",
	})

	// Notify the originating conversation. Single message — the
	// agent-builder's exit tool already produced the user-facing summary
	// (successMsg), so no LLM follow-up turn is needed.
	if input.ConversationID != "" && b.upgradeNotifier != nil {
		msg := successMsg
		if msg == "" {
			msg = "Upgrade complete: " + input.Description
		}
		if err := b.upgradeNotifier.NotifyUpgradeComplete(dbCtx, agentUUID, input.ConversationID, "success", msg); err != nil {
			b.logger.Error("post-upgrade notification failed", zap.Error(err))
		}
	}
}

// autoFixContextFromInput returns a populated AutoFixContext when the
// UpgradeInput carries any failure context (auto_fix path), otherwise
// nil. Execute uses the nil/non-nil distinction to decide whether to
// write DIAGNOSTICS.md before invoking Sol.
func autoFixContextFromInput(input UpgradeInput) *AutoFixContext {
	if input.ErrorMessage == "" && input.PanicTrace == "" && input.InputPayload == "" && input.Actions == "" && input.Messages == "" && input.Logs == "" {
		return nil
	}
	return &AutoFixContext{
		ErrorMessage: input.ErrorMessage,
		PanicTrace:   input.PanicTrace,
		InputPayload: input.InputPayload,
		Actions:      input.Actions,
		Messages:     input.Messages,
		Logs:         input.Logs,
	}
}
