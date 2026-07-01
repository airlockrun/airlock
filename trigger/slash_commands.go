package trigger

import (
	"context"
	"fmt"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
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
	{Name: "cancel", Description: "Stop the current run", Access: agentsdk.AccessPublic},
	{Name: "clear", Description: "Clear conversation context", Access: agentsdk.AccessUser},
	{Name: "compact", Description: "Summarize and compact context", Access: agentsdk.AccessUser},
	{Name: "echo", Description: "Toggle tool output bubbles (on / off / blank=flip)", Access: agentsdk.AccessUser},
}

// RunCanceler is the slice of *Dispatcher that the agent-path slash
// conv adapter uses to fire /cancel. Defined as an interface so tests
// can stub without standing up containers / DB / encryptor.
type RunCanceler interface {
	CancelRun(runID uuid.UUID) bool
}

// isStartCommand reports whether text is the /start command (tolerating a
// @botname suffix or a deep-link payload). Used to bind the web-app menu button
// on the user's actual /start rather than an earlier service message.
func isStartCommand(text string) bool {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return false
	}
	cmd := fields[0]
	if at := strings.IndexByte(cmd, '@'); at >= 0 {
		cmd = cmd[:at]
	}
	return strings.EqualFold(cmd, "/start")
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
// produces the user-visible text via a normal run. ForwardAsCompact is
// agent-path only; the sysagent path runs compact inline and returns the
// summary in Reply.
type SlashCommandResult struct {
	Handled          bool
	Reply            string
	ForwardAsCompact bool
}

// SlashConv is the per-conversation backing the slash-command dispatcher
// operates against. Two implementations: agentConvAdapter (agent
// bridges, web chat) and sysagentConvAdapter (system bridges → sysagent).
// Each method is the full compound operation the corresponding /command
// performs, not a primitive query — the per-conversation table choice
// stays inside the adapter.
type SlashConv interface {
	// Cancel aborts the latest live run on this conversation. Returns
	// true if a cancel was dispatched, false if there was nothing in
	// flight (or the cancel target couldn't be reached, e.g. process
	// restart cleared the in-memory dispatcher state).
	Cancel(ctx context.Context, convID pgtype.UUID) bool

	// Clear advances the conversation's context checkpoint to a fresh
	// marker message and resolves any lingering suspended run. Returns
	// whether a suspension was cleared so the reply can mention it.
	Clear(ctx context.Context, convID pgtype.UUID) (suspensionCleared bool, err error)

	// Compact compacts the conversation's history. Agent path: returns
	// (forward=true) so TrySlashCommand sets ForwardAsCompact and the
	// agent container runs Sol.Runner.Compact, emitting the summary as
	// a normal assistant message. Sysagent path: runs compaction
	// in-process and returns (summary, forward=false).
	Compact(ctx context.Context, convID pgtype.UUID) (reply string, forward bool, err error)

	// Echo updates the "show tool output bubbles" setting and returns
	// the resulting state. args is the raw post-/echo token ("on",
	// "off", or empty for toggle).
	Echo(ctx context.Context, convID pgtype.UUID, args string) (on bool, err error)

	// Start returns the onboarding reply for /start — a greeting that names
	// the bot's agent binding (agent bridge) or introduces the system
	// assistant (system bridge). It does not gate on membership: a linked
	// user at any access level (Public included) is welcome. Unlinked users
	// never reach here — the bridge DMs a signed auth link upstream.
	Start(ctx context.Context, convID pgtype.UUID) string
}

// bridgePrincipal maps a resolved bridge user to an authz.Principal: an
// anonymous public-channel caller (uuid.Nil) becomes AnonymousPrincipal,
// a linked user becomes a registered-user principal. Tenant role is not
// consulted on the per-agent axis, so it's left empty. The prompt path
// uses this to resolve CallerAccess through the one authz resolver.
func bridgePrincipal(userID uuid.UUID) authz.Principal {
	if userID == uuid.Nil {
		return authz.AnonymousPrincipal()
	}
	return authz.UserPrincipal(userID, "")
}

// TrySlashCommand parses message for a leading slash command and, if
// recognized, dispatches it against conv. Returns Handled=false when the
// message is a plain user prompt — callers forward it to the agent (or
// sysagent) as usual.
//
// access is the caller's resolved agent access; commands gate against
// SlashCommand.Access. /clear, /echo, /compact, /cancel route into
// SlashConv; /auth replies with the already-linked acknowledgement
// (the un-linked path is handled by the bridge before identity lookup).
func TrySlashCommand(
	ctx context.Context,
	conv SlashConv,
	convID pgtype.UUID,
	access agentsdk.Access,
	message string,
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

	// /start is Telegram's onboarding command — the START button every new
	// user taps. Reply with a greeting that names the agent binding rather
	// than forwarding to the agent (which does nothing useful for a fresh
	// user) or hitting the unknown-command path below. Not in Registry: it's
	// a Telegram built-in, never shown in the custom command menu.
	if name == "start" {
		return SlashCommandResult{Handled: true, Reply: conv.Start(ctx, convID)}, nil
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

	if !authz.AccessAtLeast(access, entry.Access) {
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

	case "cancel":
		if conv.Cancel(ctx, convID) {
			return SlashCommandResult{Handled: true, Reply: "Run cancelled."}, nil
		}
		return SlashCommandResult{Handled: true, Reply: "Nothing to cancel."}, nil

	case "clear":
		sus, err := conv.Clear(ctx, convID)
		if err != nil {
			return SlashCommandResult{Handled: true, Reply: "Failed to clear context: " + err.Error()}, err
		}
		reply := "Context cleared."
		if sus {
			reply += " Pending confirmation cancelled."
		}
		return SlashCommandResult{Handled: true, Reply: reply}, nil

	case "compact":
		reply, forward, err := conv.Compact(ctx, convID)
		if err != nil {
			return SlashCommandResult{Handled: true, Reply: "Failed to compact: " + err.Error()}, err
		}
		return SlashCommandResult{Handled: true, Reply: reply, ForwardAsCompact: forward}, nil

	case "echo":
		next, err := conv.Echo(ctx, convID, args)
		if err != nil {
			return SlashCommandResult{Handled: true, Reply: "Failed to update echo: " + err.Error()}, err
		}
		if next {
			return SlashCommandResult{Handled: true, Reply: "Echo: on. Tool output will be shown."}, nil
		}
		return SlashCommandResult{Handled: true, Reply: "Echo: off. Tool output will be hidden (errors still shown)."}, nil
	}
	return SlashCommandResult{Handled: true, Reply: "Unhandled command"}, nil
}
