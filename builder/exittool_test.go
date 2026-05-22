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
		{name: "success accepted", status: "success"},
		{name: "error accepted", status: "error"},
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

func TestNewExitToolNilState(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil ExitState")
		}
	}()
	newExitTool(nil)
}
