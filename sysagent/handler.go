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
	return s.notifyAndResume(ctx, agentID, conversationID, prefix, source, message)
}

// NotifyBuildComplete satisfies builder.PostBuildSystemNotifier — the
// initial-build counterpart of NotifyUpgradeComplete. Triggered after a
// build kicked off from the system-agent create_agent tool finishes; same
// inject-then-resume mechanism, build-flavored prefix.
func (s *Service) NotifyBuildComplete(ctx context.Context, agentID, conversationID uuid.UUID, status, message string) error {
	prefix, source := buildOutcomeRendering(status)
	return s.notifyAndResume(ctx, agentID, conversationID, prefix, source, message)
}

// notifyAndResume injects a user-role outcome message into a system-agent
// conversation and kicks an auto-resume LLM turn so the agent reacts. Shared
// by the upgrade and build notifiers; prefix/source are pre-rendered by the
// caller for the specific outcome.
func (s *Service) notifyAndResume(ctx context.Context, agentID, conversationID uuid.UUID, prefix, source, message string) error {
	body := prefix + message

	// 1. Persist the user-role injection (web + bridge alike). content is
	//    the plain-text display string; parts stays NULL — same shape
	//    agent_messages uses for a single-text payload. source="upgrade"/
	//    "error" drives bubble styling. The next history load picks it up,
	//    and the auto-resume turn below reacts to it.
	if err := s.appendInjectedMessage(ctx, conversationID, "user", source, body, nil); err != nil {
		return fmt.Errorf("append outcome-notify message: %w", err)
	}

	// 2. Resolve the delivery channel from the conversation row — same
	//    decision the agent path makes (api/conversations.go
	//    NotifyUpgradeComplete): a bridge thread (source="bridge" + bridge_id
	//    + external_id) is delivered out-of-band by the bridge poster; a web
	//    thread streams over the WS pubsub.
	q := dbq.New(s.db.Pool())
	conversation, err := q.GetSystemConversationByID(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		return fmt.Errorf("load conversation for outcome-notify: %w", err)
	}
	isBridge := conversation.Source == "bridge" && conversation.BridgeID.Valid &&
		conversation.ExternalID.Valid && conversation.ExternalID.String != "" && s.bridgeResumer != nil

	// 3. Web only: publish a NotificationEvent on the owner's WS topic so the
	//    UI bubble renders live before the auto-resume reply streams. Bridges
	//    have no such channel — their user already knows they triggered the
	//    build; we deliver the resume reply itself (step 4).
	if !isBridge {
		partsForWS, err := json.Marshal([]map[string]any{{
			"type":   "text",
			"text":   body,
			"source": source,
		}})
		if err != nil {
			return fmt.Errorf("marshal outcome-notify parts: %w", err)
		}
		userID := uuid.UUID(conversation.UserID.Bytes)
		env := realtime.NewEnvelopeForUser("notification", userID.String(), userID.String(), conversationID.String(),
			&airlockv1.NotificationEvent{
				AgentId:        agentID.String(), // agent that was built, not the sysagent itself
				ConversationId: conversationID.String(),
				PartsJson:      string(partsForWS),
				Source:         source,
			})
		if pserr := s.pubsub.Publish(ctx, userID, env); pserr != nil {
			s.logger.Warn("sysagent: notification publish failed",
				zap.Stringer("conversation", conversationID), zap.Error(pserr))
			// Not fatal — the next conversation load picks up the message
			// from the DB even if the live event was dropped.
		}
	}

	// 4. Trigger the auto-resume: a fresh LLM turn with the injected message
	//    in history. Background context — the notifier's caller (the builder
	//    goroutine) shouldn't block on the resumed run. Bridge threads route
	//    through resumeToBridge (capture the reply, push via SendParts); web
	//    threads stream through resumeConversation's WS path.
	go func() {
		bg := context.Background()
		if isBridge {
			if err := s.bridgeResumer.ResumeSystemConversation(bg, conversationID); err != nil {
				s.logger.Error("sysagent: bridge auto-resume after outcome-notify failed",
					zap.Stringer("conversation", conversationID), zap.Error(err))
			}
			return
		}
		if err := s.resumeConversation(bg, conversationID); err != nil {
			s.logger.Error("sysagent: auto-resume after outcome-notify failed",
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

// buildOutcomeRendering returns (prefix, source) for an initial build's two
// outcomes. Reuses the upgrade bubble sources ("upgrade"/"error") so the UI
// renders these notifications identically; only the prefix differs.
func buildOutcomeRendering(status string) (prefix, source string) {
	switch status {
	case "success":
		return "[Build succeeded] ", "upgrade"
	case "error":
		return "[Build failed] ", "error"
	}
	return "[Build " + status + "] ", "upgrade"
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
