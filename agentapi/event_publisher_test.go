package agentapi

import (
	"encoding/json"
	"testing"

	"github.com/airlockrun/goai/message"
)

func TestDecodeToolOutput(t *testing.T) {
	marshal := func(o message.ToolResultOutput) json.RawMessage {
		raw, err := message.MarshalOutput(o)
		if err != nil {
			t.Fatalf("MarshalOutput: %v", err)
		}
		return raw
	}

	tests := []struct {
		name        string
		raw         json.RawMessage
		wantText    string
		wantOutcome string
		wantErrText string
	}{
		{
			name:        "text success",
			raw:         marshal(message.TextOutput{Value: "hello"}),
			wantText:    "hello",
			wantOutcome: "success",
			wantErrText: "",
		},
		{
			name:        "json success",
			raw:         marshal(message.JSONOutput{Value: map[string]any{"ok": true}}),
			wantText:    `{"ok":true}`,
			wantOutcome: "success",
			wantErrText: "",
		},
		{
			// The bug: an error must populate only errText. If text were
			// also set, the call site puts it in both Output and Error and
			// ToolBadge renders it twice (black + red).
			name:        "error-text routes to errText only",
			raw:         marshal(message.ErrorTextOutput{Value: "ReferenceError: x is not defined"}),
			wantText:    "",
			wantOutcome: "error",
			wantErrText: "ReferenceError: x is not defined",
		},
		{
			name:        "execution-denied keeps reason in text",
			raw:         marshal(message.ExecutionDeniedOutput{Reason: "denied by user"}),
			wantText:    "denied by user",
			wantOutcome: "denied",
			wantErrText: "",
		},
		{
			name:        "empty is empty success",
			raw:         nil,
			wantText:    "",
			wantOutcome: "success",
			wantErrText: "",
		},
		{
			name:        "null is empty success",
			raw:         json.RawMessage("null"),
			wantText:    "",
			wantOutcome: "success",
			wantErrText: "",
		},
		{
			name:        "malformed falls back to raw text success",
			raw:         json.RawMessage(`not json`),
			wantText:    "not json",
			wantOutcome: "success",
			wantErrText: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, outcome, errText := decodeToolOutput(tt.raw)
			if text != tt.wantText {
				t.Errorf("text = %q, want %q", text, tt.wantText)
			}
			if outcome != tt.wantOutcome {
				t.Errorf("outcome = %q, want %q", outcome, tt.wantOutcome)
			}
			if errText != tt.wantErrText {
				t.Errorf("errText = %q, want %q", errText, tt.wantErrText)
			}
		})
	}
}

func TestNewCompactionFinishedEvent(t *testing.T) {
	event := newCompactionFinishedEvent("run-123", json.RawMessage(`{"tokensFreed":27,"error":"store failed"}`))
	if event.RunId != "run-123" || event.TokensFreed != 27 || event.Error != "store failed" {
		t.Fatalf("event = %+v", event)
	}
}
