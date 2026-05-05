package trigger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// SlashCommand describes a user-typable command. Registry is the single
// source of truth: TrySlashCommand dispatches from it, and bridge drivers
// that support native command menus (Telegram setMyCommands, etc.) expose
// it verbatim. Name is stored without the leading slash.
type SlashCommand struct {
	Name        string
	Description string
	Access      agentsdk.Access
}

// Registry is the canonical list of commands. Order is preserved when
// rendered into platform command menus.
var Registry = []SlashCommand{
	{Name: "auth", Description: "Link your Airlock account", Access: agentsdk.AccessPublic},
	{Name: "clear", Description: "Clear conversation context", Access: agentsdk.AccessUser},
	{Name: "compact", Description: "Summarize and compact context", Access: agentsdk.AccessUser},
	{Name: "echo", Description: "Toggle tool output bubbles (on / off / blank=flip)", Access: agentsdk.AccessUser},
}

// findCommand returns the registry entry for name (without leading slash)
// or nil if not registered.
func findCommand(name string) *SlashCommand {
	for i := range Registry {
		if Registry[i].Name == name {
			return &Registry[i]
		}
	}
	return nil
}

// SlashCommandResult is the outcome of handling a slash command.
// Handled=false means the message was not a slash command — callers should
// forward it to the agent as usual. Handled=true means the command was
// recognized and processed. Reply is the short message to show the user,
// unless ForwardAsCompact is set — in that case the caller should invoke
// the agent with PromptInput.ForceCompact=true so Sol's summarization
// produces the user-visible text via a normal run.
type SlashCommandResult struct {
	Handled          bool
	Reply            string
	ForwardAsCompact bool
}

// ResolveAgentAccess returns the caller's effective per-agent access level
// from agent_members. Non-members get AccessPublic, members map straight
// to AccessUser or AccessAdmin. Tenant role is deliberately not consulted —
// see airlock/CLAUDE.md "Permission Model" for why these axes are separate.
func ResolveAgentAccess(ctx context.Context, q *dbq.Queries, agentID, userID uuid.UUID) agentsdk.Access {
	if userID == uuid.Nil {
		return agentsdk.AccessPublic
	}
	member, err := q.GetAgentMember(ctx, dbq.GetAgentMemberParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
		UserID:  pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return agentsdk.AccessPublic
	}
	if member.Role == "admin" {
		return agentsdk.AccessAdmin
	}
	return agentsdk.AccessUser
}

// accessRank orders access levels for comparison. AccessAdmin > AccessUser > AccessPublic.
func accessRank(a agentsdk.Access) int {
	switch a {
	case agentsdk.AccessAdmin:
		return 2
	case agentsdk.AccessUser:
		return 1
	default:
		return 0
	}
}

// TrySlashCommand parses message for a leading slash command and, if recognized,
// executes it against the conversation. Returns Handled=false when the message
// is a plain user prompt. Both web (api.conversationsHandler.Prompt) and bridge
// (PromptProxy) paths call this before forwarding to the agent.
//
// access is the caller's resolved agent access (see ResolveAgentAccess) and is
// compared against the command's required level. agentID is used by /clear to
// resolve any pending suspended run so the pending-confirmation dialog doesn't
// linger after context clear.
func TrySlashCommand(
	ctx context.Context,
	q *dbq.Queries,
	convID pgtype.UUID,
	agentID uuid.UUID,
	access agentsdk.Access,
	message string,
	logger *zap.Logger,
) (SlashCommandResult, error) {
	trimmed := strings.TrimSpace(message)
	if !strings.HasPrefix(trimmed, "/") {
		return SlashCommandResult{}, nil
	}

	parts := strings.SplitN(trimmed, " ", 2)
	name := strings.ToLower(strings.TrimPrefix(parts[0], "/"))
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}

	entry := findCommand(name)
	if entry == nil {
		names := make([]string, len(Registry))
		for i, c := range Registry {
			names[i] = "/" + c.Name
		}
		return SlashCommandResult{
			Handled: true,
			Reply:   fmt.Sprintf("Unknown command /%s. Available: %s.", name, strings.Join(names, ", ")),
		}, nil
	}

	if accessRank(access) < accessRank(entry.Access) {
		return SlashCommandResult{
			Handled: true,
			Reply:   fmt.Sprintf("/%s requires %s access.", entry.Name, entry.Access),
		}, nil
	}

	switch entry.Name {
	case "auth":
		// Already-linked path: bridge intercepts /auth above identity
		// lookup and DMs the link there. If we got here, the caller is
		// either already linked (bridge path past identity lookup) or
		// signed in via web — either way nothing to bind.
		return SlashCommandResult{Handled: true, Reply: "You are already linked."}, nil
	case "clear":
		reply, err := handleClearCommand(ctx, q, convID, agentID, logger)
		if err != nil {
			return SlashCommandResult{Handled: true, Reply: "Failed to clear context: " + err.Error()}, err
		}
		return SlashCommandResult{Handled: true, Reply: reply}, nil
	case "compact":
		// The agent container runs the actual summarization via Sol's
		// Runner.Compact path. Airlock only forwards the request with
		// ForceCompact=true; the agent emits the user-visible reply.
		return SlashCommandResult{Handled: true, ForwardAsCompact: true}, nil
	case "echo":
		reply, err := handleEchoCommand(ctx, q, convID, args)
		if err != nil {
			return SlashCommandResult{Handled: true, Reply: "Failed to update echo: " + err.Error()}, err
		}
		return SlashCommandResult{Handled: true, Reply: reply}, nil
	}
	return SlashCommandResult{Handled: true, Reply: "Unhandled command"}, nil
}

// handleClearCommand advances the conversation's context checkpoint to a newly
// inserted marker row — forgetting prior LLM context without deleting history
// from the DB. The marker is rendered by the UI as a "context cleared" divider
// annotated with how many tokens were freed.
//
// If there's a pending suspended run for the agent, it's resolved too. A
// pending tool confirmation against the now-forgotten context is not useful,
// and leaving the run suspended would surface a stale confirmation dialog on
// the next page reload.
func handleClearCommand(ctx context.Context, q *dbq.Queries, convID pgtype.UUID, agentID uuid.UUID, logger *zap.Logger) (string, error) {
	tokensFreed, err := q.SumPreCheckpointTokens(ctx, convID)
	if err != nil {
		return "", fmt.Errorf("sum pre-checkpoint tokens: %w", err)
	}

	markerParts, err := json.Marshal([]map[string]any{{
		"type":        "checkpoint",
		"kind":        "clear",
		"tokensFreed": tokensFreed,
	}})
	if err != nil {
		return "", fmt.Errorf("marshal marker parts: %w", err)
	}

	marker, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
		ConversationID: convID,
		Role:           "system",
		Content:        "",
		Parts:          markerParts,
		RunID:          pgtype.UUID{},
		Source:         "checkpoint",
	})
	if err != nil {
		return "", fmt.Errorf("create checkpoint marker: %w", err)
	}

	if err := q.SetConversationCheckpoint(ctx, dbq.SetConversationCheckpointParams{
		ConversationID:      convID,
		CheckpointMessageID: marker.ID,
	}); err != nil {
		return "", fmt.Errorf("set checkpoint: %w", err)
	}

	// Best-effort: clear any lingering suspended run. A resolve failure logs
	// a warning but doesn't fail the /clear — the checkpoint has already
	// advanced, and the caller gets the normal confirmation.
	suspensionCleared := false
	if sus, err := q.GetLatestSuspendedRun(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err == nil {
		if rerr := q.ResolveSuspendedRun(ctx, sus.ID); rerr != nil {
			if logger != nil {
				logger.Warn("resolve suspended run during /clear", zap.Error(rerr))
			}
		} else {
			suspensionCleared = true
		}
	}

	reply := fmt.Sprintf("Context cleared. %d tokens freed.", tokensFreed)
	if suspensionCleared {
		reply += " Pending confirmation cancelled."
	}
	return reply, nil
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

// handleEchoCommand writes settings.echo to the conversation row. Accepts
// "on", "off", or blank (toggle). Toggle flips from the currently stored
// explicit value, treating unset as off — so the first `/echo` in a chat
// that's quiet by default always turns echo on, which matches user intent.
func handleEchoCommand(ctx context.Context, q *dbq.Queries, convID pgtype.UUID, args string) (string, error) {
	arg := strings.ToLower(strings.TrimSpace(args))
	var next bool
	switch arg {
	case "on":
		next = true
	case "off":
		next = false
	case "":
		conv, err := q.GetConversationByID(ctx, convID)
		if err != nil {
			return "", fmt.Errorf("get conversation: %w", err)
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
		return "Usage: /echo [on|off]. Blank toggles.", nil
	}

	patch, err := json.Marshal(map[string]any{"echo": next})
	if err != nil {
		return "", fmt.Errorf("marshal patch: %w", err)
	}
	if err := q.UpdateConversationSettings(ctx, dbq.UpdateConversationSettingsParams{
		ID:    convID,
		Patch: patch,
	}); err != nil {
		return "", fmt.Errorf("update settings: %w", err)
	}

	if next {
		return "Echo: on. Tool output will be shown.", nil
	}
	return "Echo: off. Tool output will be hidden (errors still shown).", nil
}
