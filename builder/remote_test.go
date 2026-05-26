package builder

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestPatAuthExtraHeader(t *testing.T) {
	a := &patAuth{token: "ghp_secret"}
	header, err := a.ExtraHeader(context.Background())
	if err != nil {
		t.Fatalf("ExtraHeader: %v", err)
	}
	const prefix = "Authorization: Basic "
	if !strings.HasPrefix(header, prefix) {
		t.Fatalf("header = %q, want prefix %q", header, prefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := "x-access-token:ghp_secret"
	if string(decoded) != want {
		t.Errorf("decoded = %q, want %q", decoded, want)
	}
}

func TestIsNonFastForward(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"non-fast-forward verbatim", errors.New("exit 1: ! [rejected] main -> main (non-fast-forward)"), true},
		{"updates were rejected", errors.New("exit 1: Updates were rejected because the tip of your current branch is behind"), true},
		{"hint fetch first", errors.New("exit 1: hint: ('git pull ...') before pushing again. hint: See the 'Note about fast-forwards' in 'git push --help' for details. fetch first"), true},
		{"network failure (not nff)", errors.New("exit 128: fatal: unable to access 'https://...': Could not resolve host"), false},
		{"auth failure (not nff)", errors.New("exit 128: fatal: Authentication failed"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNonFastForward(tt.err); got != tt.want {
				t.Errorf("isNonFastForward(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestPushConflictError(t *testing.T) {
	e := &PushConflictError{PreservedBranch: "airlock/upgrade/run-123", RemoteBranch: "main"}
	msg := e.Error()
	for _, want := range []string{"main", "airlock/upgrade/run-123", "preserved"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, missing %q", msg, want)
		}
	}
	// Also: errors.As recovers the typed error.
	var pce *PushConflictError
	if !errors.As(e, &pce) {
		t.Error("errors.As failed to extract *PushConflictError")
	}
}
