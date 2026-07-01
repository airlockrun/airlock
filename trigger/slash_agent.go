package trigger

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// AgentSlashConv is the SlashConv implementation for agent-bridge and
// web conversations stored in agent_conversations / agent_messages.
// /compact forwards to the agent container (sets ForwardAsCompact);
// every other command operates locally against the airlock DB.
type AgentSlashConv struct {
	q        *dbq.Queries
	canceler RunCanceler
	logger   *zap.Logger
	agentID  uuid.UUID
}

// NewAgentSlashConv builds an adapter for the agent-conversation path.
// canceler dispatches /cancel into the agent dispatcher; nil yields the
// "Nothing to cancel" path on restart (no live in-memory state). agentID
// identifies the bound agent so /start can name it even before any
// conversation exists (slash commands don't create one).
func NewAgentSlashConv(q *dbq.Queries, canceler RunCanceler, logger *zap.Logger, agentID uuid.UUID) *AgentSlashConv {
	return &AgentSlashConv{q: q, canceler: canceler, logger: logger, agentID: agentID}
}

// Cancel — q.GetLatestRunningPromptRun then dispatcher.CancelRun. The
// HTTP-request abort is what flips the run row out of 'running' (via the
// agent's r.Complete or the stuck-run sweeper as a backstop).
func (a *AgentSlashConv) Cancel(ctx context.Context, convID pgtype.UUID) bool {
	if !convID.Valid {
		return false
	}
	convIDStr := uuid.UUID(convID.Bytes).String()
	row, err := a.q.GetLatestRunningPromptRun(ctx, convIDStr)
	if err != nil {
		return false
	}
	if a.canceler == nil {
		return false
	}
	return a.canceler.CancelRun(uuid.UUID(row.Bytes))
}

// Clear writes a checkpoint marker row and advances the conversation's
// context_checkpoint_message_id. Also best-effort resolves any
// suspended run for THIS conversation (not a sibling-delegated
// suspension that happens to be the agent's latest).
func (a *AgentSlashConv) Clear(ctx context.Context, convID pgtype.UUID) (bool, error) {
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

	marker, err := a.q.CreateMessage(ctx, dbq.CreateMessageParams{
		ConversationID: convID,
		Role:           "system",
		Content:        "",
		Parts:          markerParts,
		RunID:          pgtype.UUID{},
		Source:         "checkpoint",
	})
	if err != nil {
		return false, fmt.Errorf("create checkpoint marker: %w", err)
	}

	if err := a.q.SetConversationCheckpoint(ctx, dbq.SetConversationCheckpointParams{
		ConversationID:      convID,
		CheckpointMessageID: marker.ID,
	}); err != nil {
		return false, fmt.Errorf("set checkpoint: %w", err)
	}

	suspensionCleared := false
	if sus, err := a.q.GetLatestSuspendedRunByConversation(ctx, uuid.UUID(convID.Bytes).String()); err == nil {
		if rerr := a.q.ResolveSuspendedRun(ctx, sus.ID); rerr != nil {
			if a.logger != nil {
				a.logger.Warn("resolve suspended run during /clear", zap.Error(rerr))
			}
		} else {
			suspensionCleared = true
		}
	}
	return suspensionCleared, nil
}

// Compact is a no-op locally: the agent container runs the actual
// summarization via Sol.Runner.Compact, so we just signal "forward as
// compact" and let the proxy set ForceCompact=true on the forwarded
// request.
func (a *AgentSlashConv) Compact(_ context.Context, _ pgtype.UUID) (string, bool, error) {
	return "", true, nil
}

// Echo flips the conversation's settings.echo flag. Toggle treats unset
// as off so the first /echo in a chat that's quiet by default always
// turns echo on.
func (a *AgentSlashConv) Echo(ctx context.Context, convID pgtype.UUID, args string) (bool, error) {
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
		conv, err := a.q.GetConversationByID(ctx, convID)
		if err != nil {
			return false, fmt.Errorf("get conversation: %w", err)
		}
		var s conversationSettings
		if len(conv.Settings) > 0 {
			_ = json.Unmarshal(conv.Settings, &s)
		}
		cur := false
		if s.Echo != nil {
			cur = *s.Echo
		}
		next = !cur
	default:
		return false, fmt.Errorf("usage: /echo [on|off]")
	}

	patch, err := json.Marshal(map[string]any{"echo": next})
	if err != nil {
		return false, fmt.Errorf("marshal patch: %w", err)
	}
	if err := a.q.UpdateConversationSettings(ctx, dbq.UpdateConversationSettingsParams{
		ID:    convID,
		Patch: patch,
	}); err != nil {
		return false, fmt.Errorf("update settings: %w", err)
	}
	return next, nil
}

// Start greets the user and names the bound agent. Resolved from agentID, not
// the conversation — /start runs before any conversation exists. Access is not
// consulted: every linked user is welcome (a member can hold Public access).
func (a *AgentSlashConv) Start(ctx context.Context, convID pgtype.UUID) string {
	name := "this agent"
	if ag, err := a.q.GetAgentByID(ctx, toPgUUID(a.agentID)); err == nil && ag.Name != "" {
		name = ag.Name
	}
	return "👋 Hi! You're connected to " + name + ". Send me a message to get started."
}

// conversationSettings is the typed view over agent_conversations.settings.
// Fields use pointers so we can distinguish "unset — follow driver default"
// from "explicitly false".
type conversationSettings struct {
	Echo *bool `json:"echo,omitempty"`
}

// ResolveEcho returns the effective echo flag for a conversation given its
// raw settings JSON and the driver's default. Explicit conversation settings
// win over the driver default; missing JSON or missing key falls through to
// the default.
func ResolveEcho(settingsJSON []byte, driverDefault bool) bool {
	var s conversationSettings
	if len(settingsJSON) > 0 {
		_ = json.Unmarshal(settingsJSON, &s)
	}
	if s.Echo != nil {
		return *s.Echo
	}
	return driverDefault
}
