package sysagent

import (
	"errors"
	"strings"
	"testing"
)

func TestCapOutput(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantTruncated bool
		wantPrefix    string
	}{
		{
			name:          "under cap passes through",
			input:         strings.Repeat("a", MaxToolOutputBytes),
			wantTruncated: false,
		},
		{
			name:          "empty passes through",
			input:         "",
			wantTruncated: false,
		},
		{
			name:          "over cap is truncated with footer",
			input:         strings.Repeat("b", MaxToolOutputBytes*2),
			wantTruncated: true,
			wantPrefix:    "bbbb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := capOutput(tt.input)
			if tt.wantTruncated {
				if !strings.Contains(got, "truncated: total=") {
					t.Fatalf("expected truncation footer, got %q", got[:min(80, len(got))])
				}
				if len(got) > MaxToolOutputBytes {
					t.Fatalf("truncated output exceeds cap: len=%d cap=%d", len(got), MaxToolOutputBytes)
				}
				if !strings.HasPrefix(got, tt.wantPrefix) {
					t.Fatalf("truncated output should preserve prefix; got start=%q", got[:min(10, len(got))])
				}
				return
			}
			if got != tt.input {
				t.Fatalf("under-cap input must pass through unchanged; got len=%d want len=%d", len(got), len(tt.input))
			}
		})
	}
}

func TestOkResult_MarshalsJSON(t *testing.T) {
	res, err := okResult(map[string]int{"answer": 42})
	if err != nil {
		t.Fatalf("okResult returned error: %v", err)
	}
	// Indented form — same shape agent chat's run_js returns so
	// ToolBadge line-clipping behaves the same on both surfaces.
	if !strings.Contains(res.Output, `"answer": 42`) {
		t.Fatalf("expected indented JSON shape with %q, got %q", `"answer": 42`, res.Output)
	}
	if !strings.Contains(res.Output, "\n") {
		t.Fatalf("expected indented JSON to contain newlines, got %q", res.Output)
	}
}

func TestOkResult_AppliesCap(t *testing.T) {
	huge := strings.Repeat("z", MaxToolOutputBytes*2)
	res, err := okResult(map[string]string{"k": huge})
	if err != nil {
		t.Fatalf("okResult returned error: %v", err)
	}
	if len(res.Output) > MaxToolOutputBytes {
		t.Fatalf("okResult must cap at %d bytes, got len=%d", MaxToolOutputBytes, len(res.Output))
	}
	if !strings.Contains(res.Output, "truncated: total=") {
		t.Fatalf("expected truncation footer on oversized payload")
	}
}

func TestErrResult(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantSub string
	}{
		{"named error", errors.New("agent foo not found"), "Error: agent foo not found"},
		{"nil error guarded", nil, "Error: unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := errResult(tt.err)
			if !strings.Contains(res.Output, tt.wantSub) {
				t.Fatalf("errResult(%v).Output = %q, want substring %q", tt.err, res.Output, tt.wantSub)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
