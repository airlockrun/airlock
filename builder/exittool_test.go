package builder

import (
	"context"
	"encoding/json"
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
		{name: "success accepted", status: exitStatusSuccess},
		{name: "error accepted", status: exitStatusError},
		{name: "refused accepted", status: exitStatusRefused},
		{name: "unknown rejected", status: "bogus", wantErr: true},
		{name: "empty rejected", status: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &soltools.ExitState{}
			exit := newExitTool(state)
			in, err := json.Marshal(exitToolInput{Status: tt.status, Message: "msg"})
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}
			_, err = exit.Execute(context.Background(), in, tool.CallOptions{})
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

func TestExitToolErrorTerminatesOnFirstCall(t *testing.T) {
	var state soltools.ExitState
	exit := newExitTool(&state)

	input, err := json.Marshal(exitToolInput{Status: exitStatusError, Message: "blocked"})
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	result, err := exit.Execute(context.Background(), input, tool.CallOptions{})
	if err != nil {
		t.Fatalf("exit execute: %v", err)
	}
	if result.Title != "exit:error" {
		t.Fatalf("title = %q, want exit:error", result.Title)
	}
	if !state.Called() {
		t.Fatal("exit state was not called")
	}
	status, message := state.Result()
	if status != exitStatusError || message != "blocked" {
		t.Fatalf("state result = (%q, %q), want (%q, %q)", status, message, exitStatusError, "blocked")
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
