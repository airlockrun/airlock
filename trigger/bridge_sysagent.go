package trigger

import (
	"context"
	"fmt"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/goai/message"
	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/bus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// bridgeSink is the sysagent → bridge translator. Implements
// sol/eventstream.Sink so sysagent.runChat fans the same bus events
// the WS pubsubSink sees into the per-call ResponseEvent channel. The
// bridge driver then renders text-delta / tool-call / tool-result /
// confirmation_required exactly like agent chat.
//
// One sink per inbound bridge message — discarded once SendStream
// returns. seenPerm matches the pubsubSink's dedupe so a single
// permission-asked event lands in the channel.
type bridgeSink struct {
	out      chan<- ResponseEvent
	runID    string
	seenPerm map[string]struct{}
}

func newBridgeSink(out chan<- ResponseEvent) *bridgeSink {
	return &bridgeSink{
		out:      out,
		seenPerm: make(map[string]struct{}),
	}
}

func (b *bridgeSink) setRunID(runID uuid.UUID) {
	b.runID = runID.String()
}

func (b *bridgeSink) OnTextDelta(e stream.TextDeltaEvent) {
	b.out <- ResponseEvent{Type: "text-delta", Text: e.Text, RunID: b.runID}
}

func (b *bridgeSink) OnToolCall(e stream.ToolCallEvent) {
	b.out <- ResponseEvent{
		Type:       "tool-call",
		ToolCallID: e.ToolCallID,
		ToolName:   e.ToolName,
		ToolInput:  string(e.Input),
		RunID:      b.runID,
	}
}

func (b *bridgeSink) OnToolResult(e stream.ToolResultEvent) {
	text := message.ToolOutputText(e.Output)
	outcome := message.ToolOutcome(e.Output)
	ev := ResponseEvent{
		Type:       "tool-result",
		ToolCallID: e.ToolCallID,
		ToolName:   e.ToolName,
		RunID:      b.runID,
	}
	if outcome == "error" {
		ev.ToolError = text
	} else {
		ev.ToolOutput = text
	}
	b.out <- ev
}

func (b *bridgeSink) OnPermissionAsked(p bus.PermissionAskedPayload) {
	if p.ToolCallID != "" {
		if _, dup := b.seenPerm[p.ToolCallID]; dup {
			return
		}
		b.seenPerm[p.ToolCallID] = struct{}{}
	}
	desc, _ := p.Metadata["description"].(string)
	b.out <- ResponseEvent{
		Type:        "confirmation_required",
		RunID:       b.runID,
		Permission:  p.Permission,
		Patterns:    p.Patterns,
		Code:        pickConfirmationBody(p.Metadata),
		Description: desc,
	}
}

func (b *bridgeSink) OnAutomaticCompactionStarted(bus.AutomaticCompactionStartedPayload) {
	b.out <- ResponseEvent{Type: "compaction_started", RunID: b.runID}
}

func (b *bridgeSink) OnAutomaticCompactionFinished(p bus.AutomaticCompactionFinishedPayload) {
	b.out <- ResponseEvent{
		Type:            "compaction_finished",
		RunID:           b.runID,
		TokensFreed:     p.TokensFreed,
		CompactionError: p.Error,
	}
}

func (b *bridgeSink) OnSuspension(_ *sol.SuspensionContext) {
	// Confirmation is already delivered via OnPermissionAsked above;
	// suspension itself doesn't surface as a separate bridge event.
}

// sendOneShot pushes a single text reply through the driver's SendStream
// (the only method the BridgeDriver interface exposes for outbound
// text). Used for slash-command replies, identity-reject DMs, and the
// "use the web UI" confirmation-fallback. Errors are logged to the
// bridge manager's logger via the caller; this function swallows them
// because the calling sites are best-effort acknowledgements.
func sendOneShot(ctx context.Context, driver BridgeDriver, br dbq.Bridge, externalID, text string) {
	events := make(chan ResponseEvent, 1)
	events <- ResponseEvent{Type: "text-delta", Text: text}
	close(events)
	_, _ = driver.SendStream(ctx, br, externalID, false, events)
}

// handleSystemBridgeEvent routes a system-bridge (br.IsSystem=true)
// inbound DM into the sysagent runtime. Identity is strict — un-linked
// senders are hard-rejected ("tap /auth, complete link, then retry")
// rather than auto-binding or falling through to public-access (the
// sysagent operates with the caller's tenant permissions, so anonymous
// chat would be either useless or dangerous).
//
// The bridge poller calling us is single-threaded per-bridge, so
// inline RunPromptInline is the right serialization point — the next
// inbound DM on this bridge waits until we return.
func (m *BridgeManager) handleSystemBridgeEvent(ctx context.Context, br dbq.Bridge, event BridgeEvent) error {
	if m.sysagent == nil {
		m.logger.Warn("system bridge event dropped: sysagent runtime not attached",
			zap.String("bridge", br.Name))
		return nil
	}

	q := dbq.New(m.db.Pool())
	driver := m.drivers[br.Type]

	// /auth runs above identity lookup so an unlinked sender can opt in.
	// Reuses the agent-path handler — identity-agnostic.
	if isAuthCommand(event.Text) {
		return m.handleAuthCommand(ctx, br, driver, event)
	}

	// Cancel button tap on a sysagent run.
	if isCancelTap(event) {
		runIDStr := strings.TrimPrefix(event.Callback.Data, "cancel:")
		if runID, err := uuid.Parse(runIDStr); err == nil {
			m.sysagent.CancelRun(runID)
		}
		if tg, ok := driver.(*TelegramDriver); ok && event.Callback.AckID != "" {
			_ = tg.AnswerCallbackQuery(ctx, br.BotTokenRef, event.Callback.AckID, "Cancelled")
		}
		return nil
	}

	// Strict identity gate — no public-access fallback for system bridges.
	// On miss we DM a signed auth link (the same flow /auth uses) so the
	// user's first message (typically /start from the deep link) becomes
	// a one-tap path to linking, rather than a passive "go to airlock"
	// hint.
	identity, err := q.GetPlatformIdentity(ctx, dbq.GetPlatformIdentityParams{
		Platform:       br.Type,
		PlatformUserID: event.SenderID,
	})
	if err != nil {
		return m.handleAuthCommand(ctx, br, driver, event)
	}
	userID := pgUUID(identity.UserID)
	// Resolve the tenant role so the sysagent tool filter (buildToolSet)
	// admits tenant-axis tools (create_agent, …) for managers/admins. The
	// identity FK guarantees the user row exists — a miss is a real error.
	user, err := q.GetUserByID(ctx, identity.UserID)
	if err != nil {
		return fmt.Errorf("system bridge: resolve user tenant role: %w", err)
	}
	p := authz.UserPrincipal(userID, auth.Role(user.TenantRole))

	// Files handling. System bridges only accept voice messages — any
	// non-voice attachment is rejected with a clear message; voice
	// notes are transcribed inline and folded into the prompt text.
	// Nothing is persisted to storage on either branch.
	if len(event.Files) > 0 {
		transcript, hasVoice, hasNonVoice := m.prompter.TranscribeVoicePlain(ctx, event.Files)
		if hasNonVoice {
			sendOneShot(ctx, driver, br, event.ExternalID,
				"System chat only supports voice messages. File attachments aren't processed here.")
			return nil
		}
		if hasVoice {
			if transcript == "" {
				sendOneShot(ctx, driver, br, event.ExternalID,
					"Couldn't transcribe that voice message. Try typing it instead.")
				return nil
			}
			if event.Text == "" {
				event.Text = transcript
			} else {
				event.Text = event.Text + "\n" + transcript
			}
		}
	}

	// Per-bridge sticky sysagent thread for this user. The partial
	// unique index on (user_id, bridge_id) WHERE bridge_id IS NOT NULL
	// guarantees one row per (user, bridge); the upsert is idempotent.
	title := truncate(event.Text, 100)
	if title == "" {
		title = br.Name
	}
	conv, err := q.EnsureSystemConversationForBridge(ctx, dbq.EnsureSystemConversationForBridgeParams{
		UserID:     toPgUUID(userID),
		BridgeID:   toPgUUID(uuid.UUID(br.ID.Bytes)),
		Title:      title,
		ExternalID: pgtype.Text{String: event.ExternalID, Valid: event.ExternalID != ""},
	})
	if err != nil {
		return err
	}
	conversationID := uuid.UUID(conv.ID.Bytes)
	convPg := pgtype.UUID{Bytes: conv.ID.Bytes, Valid: true}

	// Approve/Reject button taps on a prior confirmation_required event.
	// Callback data is "approve:<runID>" or "reject:<runID>" — same
	// shape the agent path uses. Translate to RunPromptInline with
	// Approved set + ResumeRunID so sysagent's resume path
	// (dispatchResume) runs the gated tool calls and continues.
	if event.Callback != nil {
		action, resumeRunID, ok := parseCallbackData(event.Callback.Data)
		if !ok {
			if tg, ok := driver.(*TelegramDriver); ok && event.Callback.AckID != "" {
				_ = tg.AnswerCallbackQuery(ctx, br.BotTokenRef, event.Callback.AckID, "")
			}
			return nil
		}
		approved := action == "approve"
		// Strip buttons so the user can't double-tap. Best-effort.
		if event.Callback.MessageID != "" {
			_ = driver.RemoveButtons(ctx, br, event.ExternalID, event.Callback.MessageID)
		}
		respEvents := make(chan ResponseEvent, 64)
		sink := newBridgeSink(respEvents)
		driverDone := make(chan struct{})
		var driverErr error
		go func() {
			_, driverErr = driver.SendStream(ctx, br, event.ExternalID, ResolveEcho(conv.Settings, driver.DefaultEcho()), respEvents)
			close(driverDone)
		}()
		_, rerr := m.sysagent.RunPromptInline(ctx, p, conversationID, "", br.Type, &approved, resumeRunID, sink, sink.setRunID)
		close(respEvents)
		<-driverDone
		if tg, ok := driver.(*TelegramDriver); ok && event.Callback.AckID != "" {
			ackText := "Approved"
			if !approved {
				ackText = "Rejected"
			}
			_ = tg.AnswerCallbackQuery(ctx, br.BotTokenRef, event.Callback.AckID, ackText)
		}
		if driverErr != nil {
			m.logger.Error("system bridge send stream (callback) failed",
				zap.String("bridge", br.Name), zap.Error(driverErr))
		}
		if rerr != nil {
			m.logger.Error("system bridge confirmation resume failed",
				zap.String("bridge", br.Name),
				zap.String("run_id", resumeRunID),
				zap.Bool("approved", approved),
				zap.Error(rerr))
			sendOneShot(ctx, driver, br, event.ExternalID, "Confirmation failed: "+rerr.Error())
		}
		return nil
	}

	// Resolved access for slash-command gating. Sysagent has no
	// per-agent axis (no agent_members row to look up against), so
	// EffectiveAgentAccess against uuid.Nil would wrongly collapse to
	// AccessPublic and refuse user-level commands like /clear. The
	// strict identity gate at the top of this handler already proved
	// the caller is a linked airlock user, so AccessUser is the
	// correct floor here.
	access := agentsdk.AccessUser

	slashConv := NewSysagentSlashConv(m.sysagent, q, p, m.logger)
	if cmd, scerr := TrySlashCommand(ctx, slashConv, convPg, access, event.Text); scerr != nil {
		m.logger.Error("system bridge slash command failed",
			zap.String("bridge", br.Name),
			zap.String("command", event.Text),
			zap.Error(scerr))
		sendOneShot(ctx, driver, br, event.ExternalID, "Slash command failed: "+scerr.Error())
		return nil
	} else if cmd.Handled {
		if cmd.Reply != "" {
			sendOneShot(ctx, driver, br, event.ExternalID, cmd.Reply)
		}
		return nil
	}

	echo := ResolveEcho(conv.Settings, driver.DefaultEcho())

	respEvents := make(chan ResponseEvent, 64)
	sink := newBridgeSink(respEvents)
	var driverErr error
	driverDone := make(chan struct{})
	go func() {
		_, driverErr = driver.SendStream(ctx, br, event.ExternalID, echo, respEvents)
		close(driverDone)
	}()

	// RunPromptInline blocks until the run finishes (complete, error,
	// suspended, or cancelled). We close respEvents on return so
	// SendStream sees EOF and exits; the per-bridge poller pulls the
	// next inbound DM only after we return — natural serialization.
	_, err = m.sysagent.RunPromptInline(ctx, p, conversationID, event.Text, br.Type, nil, "", sink, sink.setRunID)
	close(respEvents)
	<-driverDone
	if driverErr != nil {
		m.logger.Error("system bridge send stream failed",
			zap.String("bridge", br.Name),
			zap.Error(driverErr))
	}
	if err != nil {
		m.logger.Error("system bridge run failed",
			zap.String("bridge", br.Name),
			zap.Stringer("conversation", conversationID),
			zap.Error(err))
		sendOneShot(ctx, driver, br, event.ExternalID, "System chat failed: "+err.Error())
		return nil
	}
	return nil
}

// ResumeSystemConversation runs a server-initiated auto-resume turn for a
// bridge-originated system conversation and streams it to the chat through the
// SAME bridgeSink + driver.SendStream the inbound poller uses. This is the
// delivery path for a build/upgrade completion follow-up: because it uses the
// real sink, a gated tool the resume chains into (e.g. create_tg_bot) renders
// Approve/Reject buttons in the chat — and the normal inbound callback path
// resumes the run on a tap — instead of silently suspending the way a
// text-only push would.
//
// The conversation must already carry source="bridge" + bridge_id +
// external_id (EnsureSystemConversationForBridge refreshes external_id on every
// inbound turn). Invoked by sysagent's build/upgrade notifier via the
// BridgeResumer interface; it runs synchronously and the caller drives it from
// a goroutine.
func (m *BridgeManager) ResumeSystemConversation(ctx context.Context, conversationID uuid.UUID) error {
	if m.sysagent == nil {
		return fmt.Errorf("sysagent runtime not attached")
	}
	q := dbq.New(m.db.Pool())
	conv, err := q.GetSystemConversationByID(ctx, toPgUUID(conversationID))
	if err != nil {
		return fmt.Errorf("load system conversation: %w", err)
	}
	if conv.Source != "bridge" || !conv.BridgeID.Valid || !conv.ExternalID.Valid || conv.ExternalID.String == "" {
		return fmt.Errorf("conversation %s is not a deliverable bridge thread", conversationID)
	}

	br, err := q.GetBridgeByID(ctx, conv.BridgeID)
	if err != nil {
		return fmt.Errorf("load bridge: %w", err)
	}
	user, err := q.GetUserByID(ctx, conv.UserID)
	if err != nil {
		return fmt.Errorf("load user: %w", err)
	}
	p := authz.UserPrincipal(pgUUID(conv.UserID), auth.Role(user.TenantRole))

	// Producer: the in-process run feeds the bridge sink. Consumer: the
	// shared StreamToBridge primitive renders to the chat. The sink does not
	// close the channel, so we close it once the run returns.
	respEvents := make(chan ResponseEvent, 64)
	sink := newBridgeSink(respEvents)
	var deliverErr error
	deliverDone := make(chan struct{})
	go func() {
		deliverErr = m.StreamToBridge(ctx, uuid.UUID(conv.BridgeID.Bytes), conv.ExternalID.String, conv.Settings, respEvents)
		close(deliverDone)
	}()

	// text="" + approved=nil → the auto-resume branch in runChat.
	_, runErr := m.sysagent.RunPromptInline(ctx, p, conversationID, "", br.Type, nil, "", sink, sink.setRunID)
	close(respEvents)
	<-deliverDone
	if deliverErr != nil {
		m.logger.Error("system bridge resume delivery failed",
			zap.Stringer("conversation", conversationID), zap.Error(deliverErr))
	}
	return runErr
}
