package sysagent

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/goai/message"
	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/goai/tool"
	"github.com/airlockrun/sol/bus"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

type recordingPublisher struct {
	envelopes []realtime.Envelope
}

func (p *recordingPublisher) Publish(_ context.Context, _ uuid.UUID, env realtime.Envelope) error {
	p.envelopes = append(p.envelopes, env)
	return nil
}

func TestPubsubSinkPublishesSuccessorStartBeforeResultAndConfirmation(t *testing.T) {
	publisher := &recordingPublisher{}
	conversationID := uuid.New()
	runID := uuid.New()
	userID := uuid.New()
	sink := newPubSubSink(publisher, conversationID, runID, userID, zap.NewNop())

	sink.OnRunStarted()
	sink.OnToolResult(stream.ToolResultEvent{
		ToolCallID: "call-a",
		ToolName:   "write_a",
		Output:     message.TextOutput{Value: "A complete"},
	})
	sink.OnPermissionAsked(bus.PermissionAskedPayload{
		Permission: "write_b",
		ToolCallID: "call-b",
		Metadata:   map[string]any{"args": `{"n":2}`},
	})

	var types []string
	for _, env := range publisher.envelopes {
		types = append(types, env.Type)
		if env.TopicID != userID.String() || env.UserID != userID.String() || env.ConversationID != conversationID.String() {
			t.Fatalf("envelope addressing = topic %q user %q conversation %q", env.TopicID, env.UserID, env.ConversationID)
		}
	}
	want := []string{"run.started", "run.tool_result", "run.confirmation_required"}
	if !reflect.DeepEqual(types, want) {
		t.Fatalf("event order = %v, want %v", types, want)
	}
	var started airlockv1.RunStartedEvent
	if err := protojson.Unmarshal(publisher.envelopes[0].Payload, &started); err != nil {
		t.Fatalf("decode run.started: %v", err)
	}
	if started.RunId != runID.String() || started.ConversationId != conversationID.String() {
		t.Fatalf("run.started = %+v", &started)
	}
	var confirmation airlockv1.ConfirmationRequiredEvent
	if err := protojson.Unmarshal(publisher.envelopes[2].Payload, &confirmation); err != nil {
		t.Fatalf("decode confirmation: %v", err)
	}
	if confirmation.RunId != runID.String() || confirmation.ToolCallId != "call-b" {
		t.Fatalf("confirmation = %+v", &confirmation)
	}
}

func TestPubsubSinkUsesGatedExecutorArgsForConfirmationCode(t *testing.T) {
	publisher := &recordingPublisher{}
	runBus := bus.New()
	sink := newPubSubSink(publisher, uuid.New(), uuid.New(), uuid.New(), zap.NewNop())
	unsub := sink.Forward(runBus)
	defer unsub()

	executor := newGatedExecutor(tool.NewLocalExecutor(tool.Set{}, nil))
	executor.isDestructive = func(string) bool { return true }
	ctx := bus.WithPermissionManager(context.Background(), bus.NewPermissionManager(runBus))
	input := json.RawMessage(`{"agent":"test-bot","force":true}`)
	_, err := executor.Execute(ctx, tool.Request{
		ToolCallID: "call-delete",
		ToolName:   "delete_agent",
		Input:      input,
	})
	var needed *bus.ErrPermissionNeeded
	if !errors.As(err, &needed) {
		t.Fatalf("Execute error = %v, want ErrPermissionNeeded", err)
	}
	if len(publisher.envelopes) != 1 || publisher.envelopes[0].Type != "run.confirmation_required" {
		t.Fatalf("published envelopes = %+v", publisher.envelopes)
	}
	var confirmation airlockv1.ConfirmationRequiredEvent
	if err := protojson.Unmarshal(publisher.envelopes[0].Payload, &confirmation); err != nil {
		t.Fatalf("decode confirmation: %v", err)
	}
	if confirmation.Code != string(input) {
		t.Fatalf("confirmation code = %q, want %q", confirmation.Code, input)
	}
}

func TestConfirmationRequiredEventMetadataPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]any
		want     string
	}{
		{name: "code", metadata: map[string]any{"code": "explicit", "args": "fallback"}, want: "explicit"},
		{name: "string args", metadata: map[string]any{"args": `{"n":1}`}, want: `{"n":1}`},
		{name: "structured args", metadata: map[string]any{"args": map[string]any{"n": float64(1)}}, want: `{"n":1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := confirmationRequiredEvent("run-1", bus.PermissionAskedPayload{Metadata: tt.metadata})
			if got.Code != tt.want {
				t.Fatalf("Code = %q, want %q", got.Code, tt.want)
			}
		})
	}
}
