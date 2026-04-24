package compat

import (
	"strings"
	"testing"
)

func TestCheckAgainst(t *testing.T) {
	cases := []struct {
		name     string
		reported string
		expected string
		wantErr  string // substring; "" means success
	}{
		{"exact match", "1.0.0", "1.0.0", ""},
		{"same major different minor", "1.0.0", "1.3.2", ""},
		{"same major with v prefix", "v1.2.0", "1.0.0", ""},
		{"different major low→high", "1.0.0", "2.0.0", "incompatible"},
		{"different major high→low", "2.0.0", "1.0.0", "incompatible"},
		{"reported empty", "", "1.0.0", "invalid agentsdk version"},
		{"reported non-numeric", "abc", "1.0.0", "invalid agentsdk version"},
		{"reported missing major", ".1.0", "1.0.0", "invalid agentsdk version"},
		{"expected invalid", "1.0.0", "bad", "airlock has invalid bundled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAgainst(tc.reported, tc.expected)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got success", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
