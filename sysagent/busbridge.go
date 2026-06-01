package sysagent

import (
	"context"
	"encoding/json"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/goai/message"
	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/bus"
	"github.com/airlockrun/sol/eventstream"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// pubsubSink implements eventstream.Sink by publishing typed proto
// envelopes to the realtime hub. Sysagent uses the user UUID as the WS
// topic (not the conversation UUID) — ws.go auto-subscribes each connection
// to its owner's user topic at connect, so creating a fresh conversation
// mid-session doesn't require a dynamic subscribe roundtrip. The
// conversation id rides on the envelope's ConversationID for client-side
// per-conversation routing.
//
// The proto event shapes are the SAME ones agent chat uses
// (TextDeltaEvent / ToolCallEvent / ToolResultEvent /
// ConfirmationRequiredEvent / RunCompleteEvent), so the frontend
// chat store handles agent and sysagent surfaces with one codepath.
//
// PermissionAsked dedupe: the in-process PermissionManager fires the
// event once on Ask, and the runner re-publishes it on step-complete
// (intended for the toolserver case where the two buses are
// separate). Dedupe by toolCallID so a single confirmation lands.
type pubsubSink struct {
	pubsub         *realtime.PubSub
	conversationID uuid.UUID // chat conversation; rides on envelope.ConversationID
	userID         uuid.UUID // WS topic — every sysagent event publishes here
	runID          string
	logger         *zap.Logger

	seenPerm map[string]struct{}
}

func newPubSubSink(pubsub *realtime.PubSub, conversationID, runID, userID uuid.UUID, logger *zap.Logger) *pubsubSink {
	return &pubsubSink{
		pubsub:         pubsub,
		conversationID: conversationID,
		userID:         userID,
		runID:          runID.String(),
		logger:         logger,
		seenPerm:       make(map[string]struct{}),
	}
}

// Forward subscribes this sink to b. Caller is responsible for the
// returned unsubscribe func's lifetime (defer it for the run).
func (s *pubsubSink) Forward(b *bus.Bus) func() {
	return eventstream.Forward(b, s)
}

// publish wraps a typed event in an envelope tagged with the
// sysagent's per-user gate + the conversation as conversationID, and pushes
// it onto the hub. Errors are logged and swallowed — losing a WS
// event mid-stream shouldn't tear down a chat turn.
func (s *pubsubSink) publish(eventType string, payload proto.Message) {
	env := realtime.NewEnvelopeForUser(eventType, s.userID.String(), s.userID.String(), s.conversationID.String(), payload)
	if err := s.pubsub.Publish(context.Background(), s.userID, env); err != nil {
		s.logger.Warn("sysagent: pubsub publish failed",
			zap.String("event", eventType),
			zap.String("user_topic", s.userID.String()),
			zap.String("conversation", s.conversationID.String()),
			zap.Error(err))
	}
}

func (s *pubsubSink) OnTextDelta(e stream.TextDeltaEvent) {
	s.publish("run.text_delta", &airlockv1.TextDeltaEvent{
		RunId: s.runID,
		Text:  e.Text,
	})
}

func (s *pubsubSink) OnToolCall(e stream.ToolCallEvent) {
	s.publish("run.tool_call", &airlockv1.ToolCallEvent{
		RunId:      s.runID,
		ToolCallId: e.ToolCallID,
		ToolName:   e.ToolName,
		Input:      string(e.Input),
	})
}

func (s *pubsubSink) OnToolResult(e stream.ToolResultEvent) {
	// Unwrap the discriminated ToolResultOutput into plain
	// (text, outcome, errText) — same shape api/event_publisher.go's
	// decodeToolOutput sends for agent chat, so the frontend's WS
	// handler can assign tc.output = ev.output directly without
	// re-parsing an envelope. Error text rides in `Error` (not
	// `Output`) to match the persisted-refresh path; otherwise
	// ToolBadge renders the message twice.
	text := message.ToolOutputText(e.Output)
	outcome := message.ToolOutcome(e.Output)
	out := text
	var errText string
	if outcome == "error" {
		errText = text
		out = ""
	}
	s.publish("run.tool_result", &airlockv1.ToolResultEvent{
		RunId:      s.runID,
		ToolCallId: e.ToolCallID,
		ToolName:   e.ToolName,
		Output:     out,
		Error:      errText,
		Outcome:    outcome,
	})
}

func (s *pubsubSink) OnPermissionAsked(p bus.PermissionAskedPayload) {
	if p.ToolCallID != "" {
		if _, dup := s.seenPerm[p.ToolCallID]; dup {
			return
		}
		s.seenPerm[p.ToolCallID] = struct{}{}
	}
	code, _ := p.Metadata["code"].(string)
	s.publish("run.confirmation_required", &airlockv1.ConfirmationRequiredEvent{
		RunId:      s.runID,
		Permission: p.Permission,
		Patterns:   p.Patterns,
		Code:       code,
	})
}

// OnSuspension publishes the SuspensionContext as the same
// "suspended" event agent chat uses, so the frontend's existing
// suspended-state UX (the "waiting for approval" indicator under the
// conversation) lights up unchanged. Suspension rides on RunResult, not on
// the bus, so eventstream.Forward does not call this; the chat loop
// invokes it directly after Runner.Run returns RunSuspended.
func (s *pubsubSink) OnSuspension(sc *sol.SuspensionContext) {
	if sc == nil {
		return
	}
	// The realtime.proto has no first-class SuspendedEvent today —
	// agent chat ships the suspension blob via a generic Notification.
	// Mirror that here so the frontend treats it identically.
	body, _ := json.Marshal(sc)
	s.publish("run.suspended", &airlockv1.NotificationEvent{
		AgentId:        s.conversationID.String(),
		ConversationId: s.conversationID.String(),
		PartsJson:      string(body),
		Source:         "suspension",
	})
}
