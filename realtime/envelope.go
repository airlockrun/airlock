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
type Envelope struct {
	Type      string          `json:"type"`
	RequestID string          `json:"requestId,omitempty"`
	TopicID   string          `json:"topicId,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// NewEnvelope creates an Envelope, marshaling the payload via protojson.
// The proto.Message constraint provides compile-time enforcement —
// passing map[string]any or dbq types is a compile error.
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
