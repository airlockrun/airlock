package realtime

import (
	"encoding/json"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var protoMarshal = protojson.MarshalOptions{
	UseProtoNames:   false,
	EmitUnpopulated: true,
}

// Envelope is the JSON wire format for all WebSocket messages.
//
// UserID is the principal who "owns" the event — typically the human
// at the top of a run chain. Subscribers gate delivery on
// env.UserID == conn.UserID, so a tenant admin who happens to be a
// member of agent X does not see live events from runs another user
// started on X. Pre-existing system-level broadcasts leave it empty
// and fall through to the "deliver to every subscriber on the topic"
// behaviour. ConversationID lets the frontend route an event to the
// correct chat card without payload introspection. Subagent tags an
// envelope as a sub-run event so the chat store can render it
// underneath the parent run's tool-call instead of as a top-level
// message.
type Envelope struct {
	Type           string          `json:"type"`
	RequestID      string          `json:"requestId,omitempty"`
	TopicID        string          `json:"topicId,omitempty"`
	UserID         string          `json:"userId,omitempty"`
	ConversationID string          `json:"conversationId,omitempty"`
	Subagent       *SubagentInfo   `json:"subagent,omitempty"`
	Payload        json.RawMessage `json:"payload,omitempty"`
}

// SubagentInfo identifies a sub-run when an A2A child agent's events
// are mirrored to the parent's topic. Frontend chat-store reads it to
// attach the event to the parent run's active tool-call card.
type SubagentInfo struct {
	AgentID string `json:"agentId"`
	RunID   string `json:"runId"`
	Slug    string `json:"slug,omitempty"`
}

// NewEnvelope creates an Envelope, marshaling the payload via protojson.
// The proto.Message constraint provides compile-time enforcement —
// passing map[string]any or dbq types is a compile error.
//
// This constructor leaves UserID empty, which means "deliver to every
// subscriber on the topic" — appropriate for system-level broadcasts
// (agent.synced, build events). Per-user events should use
// NewEnvelopeForUser so the WS hub can apply the user-id gate.
func NewEnvelope(eventType, topicID string, payload proto.Message) Envelope {
	var raw json.RawMessage
	if payload != nil {
		raw, _ = protoMarshal.Marshal(payload)
	}
	return Envelope{
		Type:    eventType,
		TopicID: topicID,
		Payload: raw,
	}
}

// NewEnvelopeForUser is NewEnvelope plus per-user gating + conversation
// routing. Callers that publish run events (text-delta, tool-call,
// etc.) use this so subscribers other than the run's owner don't
// receive the live stream.
func NewEnvelopeForUser(eventType, topicID, userID, conversationID string, payload proto.Message) Envelope {
	env := NewEnvelope(eventType, topicID, payload)
	env.UserID = userID
	env.ConversationID = conversationID
	return env
}

// WithSubagent tags the envelope as a sub-run event and returns it.
// Chainable on the constructors above.
func (e Envelope) WithSubagent(info SubagentInfo) Envelope {
	e.Subagent = &info
	return e
}

func errorEnvelope(requestID, msg string) Envelope {
	return Envelope{
		Type:      "error",
		RequestID: requestID,
		Payload:   mustMarshalProto(&airlockv1.ErrorEvent{Error: msg}),
	}
}

func mustMarshalProto(msg proto.Message) json.RawMessage {
	b, _ := protoMarshal.Marshal(msg)
	return b
}
