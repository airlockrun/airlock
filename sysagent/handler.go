package sysagent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// NotifyUpgradeComplete satisfies builder.PostUpgradeSystemNotifier
// for the sysagent surface. Triggered by the builder after a build
// initiated from a sysagent-conversation upgrade tool finishes (success,
// failure, or out-of-scope refusal). Mirrors agent chat's
// conversationsHandler.NotifyUpgradeComplete (api/conversations.go) so
// the operator sees the outcome through the same render path the
// LLM-driving "user message" pattern uses.
//
// What lands in the conversation: a single user-role system_messages row
// prefixed with [Upgrade succeeded] / [Upgrade failed] / [Request
// declined] — the prefix is what tells the LLM this is a
// system-injected event, not a real operator statement. Following
// agentsdk's deliberate choice not to write a separate assistant
// bubble: keeping the LLM's read of the situation unambiguous matters
// more than dual rendering.
//
// agentID is the agent that was being upgraded; the message body
// references it so the LLM has context when responding. conversationID is
// the sysagent conversation that triggered the upgrade.
func (s *Service) NotifyUpgradeComplete(ctx context.Context, agentID, conversationID uuid.UUID, status, message string) error {
	prefix, source := upgradeOutcomeRendering(status)
	body := prefix + message

	// 1. Persist the user-role injection. content is the plain-text
	//    display string; parts stays NULL — same shape agent_messages
	//    uses for a single-text payload. source="upgrade"/"error"
	//    drives bubble styling. For the WS broadcast we still build a
	//    goai-shape parts blob so the existing NotificationEvent
	//    renderer (shared with agent chat) lights up immediately.
	if err := s.appendInjectedMessage(ctx, conversationID, "user", source, body, nil); err != nil {
		return fmt.Errorf("append upgrade-notify message: %w", err)
	}
	partsForWS, err := json.Marshal([]map[string]any{{
		"type":   "text",
		"text":   body,
		"source": source,
	}})
	if err != nil {
		return fmt.Errorf("marshal upgrade-notify parts: %w", err)
	}

	// 2. Publish a notification event on the conversation owner's WS topic so
	//    the UI bubble renders live before the auto-resume's LLM reply
	//    starts streaming. Topic = user UUID (matches busbridge.go); the
	//    conversation id rides on ConversationID. Loading the user_id is a DB
	//    round-trip but the notify path runs only on build completion,
	//    not per-tool, so cheap.
	q := dbq.New(s.db.Pool())
	conversation, err := q.GetSystemConversationByID(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		return fmt.Errorf("load conversation for upgrade-notify publish: %w", err)
	}
	userID := uuid.UUID(conversation.UserID.Bytes)
	env := realtime.NewEnvelopeForUser("notification", userID.String(), userID.String(), conversationID.String(),
		&airlockv1.NotificationEvent{
			AgentId:        agentID.String(), // agent that was upgraded, not the sysagent itself
			ConversationId: conversationID.String(),
			PartsJson:      string(partsForWS),
			Source:         source,
		})
	if pserr := s.pubsub.Publish(ctx, userID, env); pserr != nil {
		s.logger.Warn("sysagent: notification publish failed",
			zap.Stringer("conversation", conversationID), zap.Error(pserr))
		// Not fatal — the next conversation load will pick up the message
		// from the DB even if the live event was dropped.
	}

	// 3. Trigger the auto-resume: a fresh LLM turn against the
	//    conversation with the new user-injected message in history. The
	//    runtime hook lives on Service.resumeConversation so chat.go can
	//    own the actual goai loop; from here we just kick it.
	go func() {
		// Background context — the notifier's caller (builder
		// goroutine) shouldn't block on the resumed LLM run, which
		// can take many seconds.
		bg := context.Background()
		if err := s.resumeConversation(bg, conversationID); err != nil {
			s.logger.Error("sysagent: auto-resume after upgrade-notify failed",
				zap.Stringer("conversation", conversationID), zap.Error(err))
		}
	}()
	return nil
}

// upgradeOutcomeRendering returns (prefix, source) for the three
// upgrade outcomes the builder reports. Matches agentsdk's prefixes
// verbatim so the LLM's training on agent chat carries over to
// sysagent without ambiguity.
func upgradeOutcomeRendering(status string) (prefix, source string) {
	switch status {
	case "success":
		return "[Upgrade succeeded] ", "upgrade"
	case "error":
		return "[Upgrade failed] ", "error"
	case "refused":
		return "[Request declined] ", "error"
	}
	// Unknown status — surface verbatim rather than dropping the
	// notification entirely. The LLM still sees something useful.
	return "[Upgrade " + status + "] ", "upgrade"
}

// appendInjectedMessage persists a system-injected message into the
// conversation WITHOUT going through the sessionStore — sessionStore is
// scoped to one chat turn's runner, while injection comes from
// outside any turn. The next chat-loop Load will pick this up via
// ListSystemMessagesByConversation the same way operator-typed messages
// are loaded.
func (s *Service) appendInjectedMessage(ctx context.Context, conversationID uuid.UUID, role, source, content string, partsJSON []byte) error {
	q := dbq.New(s.db.Pool())
	_, err := q.AppendSystemMessage(ctx, dbq.AppendSystemMessageParams{
		ConversationID: pgtype.UUID{Bytes: conversationID, Valid: true},
		Role:           role,
		Source:         source,
		Content:        content,
		Parts:          partsJSON,
		CostEstimate:   pgNumericFromFloat(0),
	})
	if err != nil {
		return err
	}
	// Touch the conversation so it bubbles up in the sidebar.
	_ = q.TouchSystemConversation(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	return nil
}

// resumeConversation kicks off a fresh chat turn against the conversation with
// whatever messages are in history. The system-injected user message
// (e.g. "[Upgrade succeeded] …") is already persisted by the caller;
// this method just starts a new run so the LLM reads the updated
// history and reacts.
//
// Principal is reconstructed from the conversation's user_id + that user's
// current tenant role. The conversation carries who owns it; the tenant
// role is looked up fresh in case it changed between the original
// upgrade trigger and the build completion. Either Principal field
// missing → abort with a logged error (the run injection still
// persists in the conversation DB-side, so the LLM will react on the next
// operator prompt instead — degraded but never silently dropped).
func (s *Service) resumeConversation(ctx context.Context, conversationID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	conversation, err := q.GetSystemConversationByID(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		return fmt.Errorf("load conversation for resume: %w", err)
	}
	user, err := q.GetUserByID(ctx, conversation.UserID)
	if err != nil {
		return fmt.Errorf("load user for resume: %w", err)
	}
	p := principalForUser(uuid.UUID(conversation.UserID.Bytes), user.TenantRole)
	if _, err := s.RunPrompt(ctx, p, conversationID, PromptInput{}); err != nil {
		return fmt.Errorf("kick auto-resume RunPrompt: %w", err)
	}
	return nil
}
