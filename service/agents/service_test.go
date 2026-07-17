package agents

import (
	"strings"
	"testing"
)

func TestSourceCommitMessage(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "missing", wantErr: true},
		{name: "custom", raw: "  Add reminders  ", want: "Add reminders"},
		{name: "blank", raw: " ", wantErr: true},
		{name: "multiline", raw: "first\nsecond", wantErr: true},
		{name: "too long", raw: strings.Repeat("x", maxSourceCommitMessageBytes+1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sourceCommitMessage(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("sourceCommitMessage(%q) returned nil error", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("sourceCommitMessage(%q): %v", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("sourceCommitMessage(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
