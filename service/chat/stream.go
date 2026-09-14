package chat

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/bus"
	"github.com/airlockrun/sol/eventstream"
)

// streamSink preserves the transport contract consumed by web and bridge
// adapters. All model orchestration runs in this process.
type streamSink struct {
	encoder *json.Encoder
	cancel  context.CancelFunc
	mu      sync.Mutex
}

func (s *streamSink) emit(kind string, data any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.encoder.Encode(struct {
		Type string `json:"type"`
		Data any    `json:"data"`
	}{kind, data}); err != nil {
		s.cancel()
	}
}
func (s *streamSink) OnTextDelta(e stream.TextDeltaEvent)   { s.emit("text-delta", e) }
func (s *streamSink) OnToolCall(e stream.ToolCallEvent)     { s.emit("tool-call", e) }
func (s *streamSink) OnToolResult(e stream.ToolResultEvent) { s.emit("tool-result", e) }
func (s *streamSink) OnPermissionAsked(e bus.PermissionAskedPayload) {
	s.emit("confirmation_required", struct {
		Permission string         `json:"permission"`
		Patterns   []string       `json:"patterns"`
		Code       string         `json:"code"`
		ToolCallID string         `json:"toolCallId"`
		Metadata   map[string]any `json:"metadata"`
	}{e.Permission, e.Patterns, stringValue(e.Metadata["code"]), e.ToolCallID, e.Metadata})
}
func (s *streamSink) OnAutomaticCompactionStarted(bus.AutomaticCompactionStartedPayload) {
	s.emit("compaction_started", struct{}{})
}
func (s *streamSink) OnAutomaticCompactionFinished(e bus.AutomaticCompactionFinishedPayload) {
	s.emit("compaction_finished", struct {
		TokensFreed int    `json:"tokensFreed"`
		Error       string `json:"error,omitempty"`
	}{e.TokensFreed, e.Error})
}

// Suspension is emitted only after its checkpoint commits.
func (s *streamSink) OnSuspension(*sol.SuspensionContext) {}
func stringValue(v any) string                            { s, _ := v.(string); return s }

var _ eventstream.Sink = (*streamSink)(nil)
