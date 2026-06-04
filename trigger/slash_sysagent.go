package trigger

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/sol/eventstream"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// SysagentRuntime is the narrow surface trigger uses from the sysagent
// package. Declared as an interface here so trigger doesn't import
// sysagent directly (sysagent → service/agents → trigger would
// cycle). *sysagent.Service satisfies this directly; api/router.go
// passes it in.
//
// RunPromptInline handles three turn shapes — fresh user message
// (text non-empty), Approve/Reject of a previously-suspended run
// (approved non-nil + resumeRunID set), or auto-resume after a
// system event (all zero). Same shape as the web RunPrompt path.
type SysagentRuntime interface {
	CancelRun(runID uuid.UUID) bool
	Compact(ctx context.Context, p authz.Principal, conversationID uuid.UUID) (string, error)
	RunPromptInline(
		ctx context.Context,
		p authz.Principal,
		conversationID uuid.UUID,
		text string,
		approved *bool,
		resumeRunID string,
		sink eventstream.Sink,
		onStart func(runID uuid.UUID),
	) (uuid.UUID, error)
}

// SysagentSlashConv is the SlashConv implementation for system bridges,
// which route inbound DMs into the in-airlock sysagent. Each method
// operates against system_conversations / system_messages / system_runs
// instead of the agent_* tables. /compact runs sol.Runner.Compact
// locally and returns the summary text (there's no agent container to
// forward to).
type SysagentSlashConv struct {
	svc    SysagentRuntime
	q      *dbq.Queries
	p      authz.Principal // bound per-request (identity-resolved bridge caller)
	logger *zap.Logger
}

// NewSysagentSlashConv builds an adapter bound to a specific resolved
// caller. Per-request (not long-lived) because the principal changes
// per inbound DM.
func NewSysagentSlashConv(svc SysagentRuntime, q *dbq.Queries, p authz.Principal, logger *zap.Logger) *SysagentSlashConv {
	return &SysagentSlashConv{svc: svc, q: q, p: p, logger: logger}
}

// Cancel — pick the latest running-or-suspended sysagent run on this
// conversation and ask the Service to interrupt its goroutine.
func (s *SysagentSlashConv) Cancel(ctx context.Context, convID pgtype.UUID) bool {
	if !convID.Valid || s.svc == nil {
		return false
	}
	runRow, err := s.q.GetLatestRunningSystemRun(ctx, convID)
	if err != nil {
		return false
	}
	return s.svc.CancelRun(uuid.UUID(runRow.Bytes))
}

// Clear writes a sysagent checkpoint marker via AppendSystemMessage and
// advances system_conversations.context_checkpoint_message_id. Also
// flips any suspended sysagent run to cancelled so the pending-
// confirmation dialog doesn't linger past the clear.
func (s *SysagentSlashConv) Clear(ctx context.Context, convID pgtype.UUID) (bool, error) {
	if !convID.Valid {
		return false, nil
	}
	markerParts, err := json.Marshal([]map[string]any{{
		"type": "checkpoint",
		"kind": "clear",
	}})
	if err != nil {
		return false, fmt.Errorf("marshal marker parts: %w", err)
	}

	marker, err := s.q.AppendSystemMessage(ctx, dbq.AppendSystemMessageParams{
		ConversationID: convID,
		Role:           "system",
		Source:         "checkpoint",
		Content:        "",
		Parts:          markerParts,
		TokensIn:       0,
		TokensOut:      0,
		// system_messages.cost_estimate is NOT NULL, so the pgtype.Numeric
		// zero value (Valid=false → NULL) gets rejected at insert time.
		// Markers are operator-side bookkeeping with no LLM cost; encode
		// the explicit 0.
		CostEstimate: pgtype.Numeric{Int: big.NewInt(0), Valid: true},
	})
	if err != nil {
		return false, fmt.Errorf("create checkpoint marker: %w", err)
	}

	if err := s.q.SetSystemConversationContextCheckpoint(ctx, dbq.SetSystemConversationContextCheckpointParams{
		ID:                  convID,
		CheckpointMessageID: pgtype.UUID{Bytes: marker.ID.Bytes, Valid: true},
	}); err != nil {
		return false, fmt.Errorf("set checkpoint: %w", err)
	}

	suspensionCleared := false
	if sus, err := s.q.GetLatestSuspendedSystemRun(ctx, convID); err == nil {
		if rerr := s.q.UpdateSystemRunStatus(ctx, dbq.UpdateSystemRunStatusParams{
			ID:           sus,
			Status:       "cancelled",
			ErrorMessage: "",
		}); rerr != nil {
			if s.logger != nil {
				s.logger.Warn("resolve suspended sysagent run during /clear", zap.Error(rerr))
			}
		} else {
			// Also clear the persisted checkpoint blob so the next turn
			// doesn't try to resume an abandoned confirmation.
			if cerr := s.q.ClearSystemConversationCheckpoint(ctx, convID); cerr != nil {
				if s.logger != nil {
					s.logger.Warn("clear sysagent suspension blob during /clear", zap.Error(cerr))
				}
			}
			suspensionCleared = true
		}
	}
	return suspensionCleared, nil
}

// Compact runs sysagent's in-process summarize-and-checkpoint and
// returns the summary text. Unlike the agent path there's no container
// to forward to.
func (s *SysagentSlashConv) Compact(ctx context.Context, convID pgtype.UUID) (string, bool, error) {
	if !convID.Valid || s.svc == nil {
		return "", false, fmt.Errorf("no conversation")
	}
	summary, err := s.svc.Compact(ctx, s.p, uuid.UUID(convID.Bytes))
	if err != nil {
		return "", false, err
	}
	return summary, false, nil
}

// Echo flips system_conversations.settings.echo via the JSONB merge
// query. Toggle treats unset as off so the first /echo always turns it
// on. Mirrors the agent-path semantics.
func (s *SysagentSlashConv) Echo(ctx context.Context, convID pgtype.UUID, args string) (bool, error) {
	if !convID.Valid {
		return false, fmt.Errorf("no conversation yet")
	}
	var next bool
	switch args {
	case "on":
		next = true
	case "off":
		next = false
	case "":
		conv, err := s.q.GetSystemConversationByID(ctx, convID)
		if err != nil {
			return false, fmt.Errorf("get sysagent conversation: %w", err)
		}
		var cur conversationSettings
		if len(conv.Settings) > 0 {
			_ = json.Unmarshal(conv.Settings, &cur)
		}
		on := false
		if cur.Echo != nil {
			on = *cur.Echo
		}
		next = !on
	default:
		return false, fmt.Errorf("usage: /echo [on|off]")
	}

	patch, err := json.Marshal(map[string]any{"echo": next})
	if err != nil {
		return false, fmt.Errorf("marshal patch: %w", err)
	}
	if err := s.q.UpdateSystemConversationSettings(ctx, dbq.UpdateSystemConversationSettingsParams{
		ID:    convID,
		Patch: patch,
	}); err != nil {
		return false, fmt.Errorf("update sysagent settings: %w", err)
	}
	return next, nil
}
