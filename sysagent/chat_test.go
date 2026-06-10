package sysagent

import (
	"encoding/json"
	"testing"

	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/bus"
)

// isDoomLoopSuspension recognises the doom-loop suspension after the
// SuspensionContext round-trips through JSON (which is the shape the
// resume path actually sees).
func TestIsDoomLoopSuspension(t *testing.T) {
	cases := []struct {
		name string
		sc   sol.SuspensionContext
		want bool
	}{
		{
			name: "doom_loop permission — match",
			sc: sol.SuspensionContext{
				Reason: "permission",
				Data:   &bus.ErrPermissionNeeded{Permission: "doom_loop", Patterns: []string{"list_runs"}},
			},
			want: true,
		},
		{
			name: "other permission — no match",
			sc: sol.SuspensionContext{
				Reason: "permission",
				Data:   &bus.ErrPermissionNeeded{Permission: "edit", Patterns: []string{"/x"}},
			},
			want: false,
		},
		{
			name: "question reason — no match",
			sc:   sol.SuspensionContext{Reason: "question"},
			want: false,
		},
		{
			name: "delegated reason — no match",
			sc:   sol.SuspensionContext{Reason: "delegated"},
			want: false,
		},
		{
			name: "empty — no match",
			sc:   sol.SuspensionContext{},
			want: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Round-trip through JSON to match what dispatchResume sees
			// (Data is `any`; after unmarshal it lands as map[string]any).
			raw, err := json.Marshal(tt.sc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got sol.SuspensionContext
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if isDoomLoopSuspension(got) != tt.want {
				t.Errorf("isDoomLoopSuspension(...) = %v, want %v", !tt.want, tt.want)
			}
		})
	}
}
