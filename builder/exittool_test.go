package builder

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/airlockrun/goai/tool"
	soltools "github.com/airlockrun/sol/tools"
)

func TestNewExitTool(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		wantErr bool
	}{
		{name: "success accepted", status: "success"},
		{name: "refused accepted", status: "refused"},
		{name: "unknown rejected", status: "bogus", wantErr: true},
		{name: "empty rejected", status: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &soltools.ExitState{}
			et := newExitTool(state)
			in, _ := json.Marshal(exitToolInput{Status: tt.status, Message: "msg"})
			_, err := et.Execute(context.Background(), in, tool.CallOptions{})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("status %q: want error, got nil", tt.status)
				}
				if state.Called() {
					t.Fatalf("status %q: ExitState set despite rejected status", tt.status)
				}
				return
			}
			if err != nil {
				t.Fatalf("status %q: unexpected error: %v", tt.status, err)
			}
			if !state.Called() {
				t.Fatalf("status %q: ExitState not set", tt.status)
			}
			gotStatus, gotMsg := state.Result()
			if gotStatus != tt.status || gotMsg != "msg" {
				t.Fatalf("Result() = (%q, %q), want (%q, msg)", gotStatus, gotMsg, tt.status)
			}
		})
	}
}

// First exit-error call is challenged (no termination, pushback message);
// the second terminates. success and refused always terminate on the
// first call (covered above).
func TestNewExitTool_ErrorIsChallengedThenAccepted(t *testing.T) {
	state := &soltools.ExitState{}
	et := newExitTool(state)
	in, _ := json.Marshal(exitToolInput{Status: "error", Message: "stuck"})

	first, err := et.Execute(context.Background(), in, tool.CallOptions{})
	if err != nil {
		t.Fatalf("first error call returned err: %v", err)
	}
	if state.Called() {
		t.Fatal("first error call set ExitState; expected pushback (no termination)")
	}
	if !strings.Contains(first.Output, "Before exiting with error") {
		t.Errorf("first error output missing pushback prefix; got: %q", first.Output)
	}

	second, err := et.Execute(context.Background(), in, tool.CallOptions{})
	if err != nil {
		t.Fatalf("second error call returned err: %v", err)
	}
	if !state.Called() {
		t.Fatal("second error call did not set ExitState; expected termination")
	}
	gotStatus, gotMsg := state.Result()
	if gotStatus != "error" || gotMsg != "stuck" {
		t.Fatalf("Result() = (%q, %q), want (\"error\", \"stuck\")", gotStatus, gotMsg)
	}
	if !strings.Contains(second.Output, "Run terminated") {
		t.Errorf("second error output should announce termination; got: %q", second.Output)
	}
}

func TestNewExitToolNilState(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil ExitState")
		}
	}()
	newExitTool(nil)
}
