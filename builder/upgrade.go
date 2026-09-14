package builder

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// PostUpgradeNotifier is called after an upgrade finishes (success,
// failure, or refusal) to post a single message into the originating
// agent conversation.
//
// status is "success", "error", or "refused". message is the
// human-readable text to surface — typically sourced from the
// agent-builder's exit tool on success, the underlying failure reason
// on error, or the out-of-scope explanation on refused. The notifier
// posts exactly ONE message and does not trigger a follow-up LLM turn —
// the agent's own exit-tool summary already describes the outcome, so
// re-prompting just produces redundant text.
type PostUpgradeNotifier interface {
	NotifyUpgradeComplete(ctx context.Context, agentID, sourceRunID uuid.UUID, conversationID, status, message string) error
}

// PostUpgradeSystemNotifier is the parallel sink for upgrades initiated
// from the in-airlock system agent (not from an agent's own
// conversation). Same status/message contract as PostUpgradeNotifier;
// the immutable async origin selects the exact initiating run and conversation.
type PostUpgradeSystemNotifier interface {
	NotifyUpgradeComplete(ctx context.Context, agentID, conversationID, originRunID uuid.UUID, status, message string) error
}

// PostBuildSystemNotifier is the initial-build counterpart of
// PostUpgradeSystemNotifier: called after a build kicked off by a
// system-agent create_agent tool finishes (success or failure), so the
// system agent surfaces the outcome and resumes. Only the system-agent
// create path sets BuildInput.ChatOriginID; the web create path
// has none and gets no notification (status shows in the build view).
type PostBuildSystemNotifier interface {
	NotifyBuildComplete(ctx context.Context, agentID, conversationID, originRunID uuid.UUID, status, message string) error
}

// UpgradeInput describes an upgrade request.
//
// ChatOriginID references the persisted initiating run. Conversation fields
// provide codegen context, not notification authority.
type UpgradeInput struct {
	ChatOriginID    pgtype.UUID
	AgentID         string
	InitiatorUserID pgtype.UUID // user who triggered the upgrade; attributes codegen spend (falls back to owner)
	RunID           string      // codegen correlation ID, not notification authority
	Reason          string      // "llm_request", "auto_fix", "manual", "source_deploy"
	Description     string      // what to change
	Message         string      // build description persisted without invoking codegen
	ConversationID  string      // conversation that triggered the upgrade (for post-upgrade reply)
	ErrorMessage    string      // from failed run (auto_fix)
	PanicTrace      string      // from failed run (auto_fix)
	InputPayload    string      // JSON of failed run input (auto_fix)
	Actions         string      // JSON of recorded actions before failure (auto_fix)
	Messages        string      // conversation messages from the failed run
	Logs            string      // captured log lines from the failed run (auto_fix)
	BuildError      string      // error_message of the agent's most recent failed build
	BuildLog        string      // tail of that build's docker log
}

// notifyUpgradeOutcome routes through the persisted source run. Unattended
// upgrades have no chat origin; chat-originated work requires its notifier.
func (b *BuildService) notifyUpgradeOutcome(ctx context.Context, agentID uuid.UUID, originID pgtype.UUID, status, message string) {
	if !originID.Valid {
		return
	}
	origin, err := dbq.New(b.db.Pool()).GetAsyncChatOrigin(ctx, originID)
	if err != nil || !origin.AgentID.Valid || uuid.UUID(origin.AgentID.Bytes) != agentID {
		b.logger.Error("invalid upgrade notification origin", zap.Error(err))
		return
	}
	if origin.SystemRunID.Valid {
		if b.upgradeSystemNotifier == nil {
			panic("builder: system upgrade notifier is required")
		}
		err = b.upgradeSystemNotifier.NotifyUpgradeComplete(ctx, agentID, uuid.UUID(origin.SystemConversationID.Bytes), uuid.UUID(origin.SystemRunID.Bytes), status, message)
	} else {
		if b.upgradeNotifier == nil {
			panic("builder: hosted upgrade notifier is required")
		}
		err = b.upgradeNotifier.NotifyUpgradeComplete(ctx, agentID, uuid.UUID(origin.SourceRunID.Bytes), uuid.UUID(origin.ConversationID.Bytes).String(), status, message)
	}
	if err != nil {
		b.logger.Error("post-upgrade notification failed", zap.Error(err))
	}
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
	unresolvedDeployment, err := qtx.AgentHasUnresolvedDeployment(ctx, agentPgUUID)
	if err != nil {
		tx.Rollback(ctx)
		return fmt.Errorf("check unresolved deployment: %w", err)
	}
	if unresolvedDeployment {
		tx.Rollback(ctx)
		return ErrUpgradeInProgress
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

	// If the agent's most recent build failed with a CODE-attributable cause
	// (compile error, migration reversibility, the agent's own exit error),
	// surface it to this upgrade's codegen via DIAGNOSTICS.md — the prior
	// codegen may have committed to main but broken the build without seeing
	// it. Platform failures (failure_kind="infra": toolserver/docker/schema/
	// deploy) are skipped: the agent can't fix a stale toolserver image, and
	// feeding it infra noise just provokes spurious changes. Best-effort.
	if last, lerr := q.GetLatestBuildForAgent(ctx, agentPgUUID); lerr == nil && last.Status == "failed" && last.FailureKind == "code" {
		input.BuildError = last.ErrorMessage
		input.BuildLog = tailLines(last.DockerLog, 100)
	}

	plan := BuildPlan{
		ChatOriginID:    input.ChatOriginID,
		Agent:           agent,
		Kind:            BuildKindUpgrade,
		Instruction:     strings.TrimSpace(input.Description),
		Message:         strings.TrimSpace(input.Message),
		Reason:          input.Reason,
		RunID:           input.RunID,
		ConversationID:  input.ConversationID,
		InitiatorUserID: input.InitiatorUserID,
		Diagnostics:     autoFixContextFromInput(input),
	}

	successMsg, runErr := b.Execute(ctx, plan)
	if runErr != nil {
		// A refused request is not an upgrade failure — the agent is
		// untouched and healthy. Release the upgrade lock back to idle
		// and tell the user the request was declined, not that the
		// upgrade broke.
		var refErr *RefusedError
		if errors.As(runErr, &refErr) {
			b.logger.Info("upgrade request declined as out of scope", zap.String("agent_id", input.AgentID))
			_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
				ID:            agentPgUUID,
				UpgradeStatus: "idle",
				ErrorMessage:  "",
			})
			b.notifyUpgradeOutcome(dbCtx, agentUUID, input.ChatOriginID, "refused", refErr.Message)
			return
		}
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
		// Surface the failure as a single conversation/conversation message —
		// without it the user only sees "still spinning" then nothing.
		// Cancellation skips the notification (the toast already covered it).
		if !errors.Is(runErr, context.Canceled) {
			b.notifyUpgradeOutcome(dbCtx, agentUUID, input.ChatOriginID, "error", errMsg)
		}
		return
	}

	b.logger.Info("upgrade completed", zap.String("agent_id", input.AgentID))
	_ = q.UpdateAgentUpgradeStatus(dbCtx, dbq.UpdateAgentUpgradeStatusParams{
		ID:            agentPgUUID,
		UpgradeStatus: "idle",
		ErrorMessage:  "",
	})

	// Notify the originating surface. Single message — the
	// agent-builder's exit tool already produced the user-facing summary
	// (successMsg), so no LLM follow-up turn is needed.
	msg := successMsg
	if msg == "" {
		msg = "Upgrade complete: " + input.Description
	}
	b.notifyUpgradeOutcome(dbCtx, agentUUID, input.ChatOriginID, "success", msg)
}

// autoFixContextFromInput returns a populated AutoFixContext when the
// UpgradeInput carries any failure context (auto_fix path), otherwise
// nil. Execute uses the nil/non-nil distinction to decide whether to
// write DIAGNOSTICS.md before invoking Sol.
// tailLines returns the last n lines of s, prefixed with an elision marker
// when content was dropped. Bounds the docker log fed into DIAGNOSTICS.md so
// a large build log doesn't blow the codegen prompt.
func tailLines(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return "… (earlier build output omitted)\n" + strings.Join(lines[len(lines)-n:], "\n")
}

func autoFixContextFromInput(input UpgradeInput) *AutoFixContext {
	if input.ErrorMessage == "" && input.PanicTrace == "" && input.InputPayload == "" && input.Actions == "" && input.Messages == "" && input.Logs == "" && input.BuildError == "" && input.BuildLog == "" {
		return nil
	}
	return &AutoFixContext{
		ErrorMessage: input.ErrorMessage,
		PanicTrace:   input.PanicTrace,
		InputPayload: input.InputPayload,
		Actions:      input.Actions,
		Messages:     input.Messages,
		Logs:         input.Logs,
		BuildError:   input.BuildError,
		BuildLog:     input.BuildLog,
	}
}
