package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// Oversized stdout/stderr in either request or response is trimmed to
// ExecRecordPreviewBytes with a marker; everything else round-trips
// unchanged.
func TestTruncateActionsJSON(t *testing.T) {
	huge := strings.Repeat("a", ExecRecordPreviewBytes*2)
	actions := []map[string]any{
		{
			"type":       "exec",
			"timestamp":  "2026-05-27T00:00:00Z",
			"durationMs": float64(123),
			"request": map[string]any{
				"slug":    "ci",
				"command": "kick-build",
			},
			"response": map[string]any{
				"exitCode":      float64(0),
				"stdout":        huge,
				"stderr":        "short stderr",
				"stdoutPreview": huge,
			},
		},
		{
			"type": "run_js",
			"request": map[string]any{
				"code": "tiny",
			},
			"response": "tiny",
		},
	}
	in, err := json.Marshal(actions)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	out := truncateActionsJSON(in)

	var got []map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal out: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d actions, want 2", len(got))
	}

	// First action: stdout + stdoutPreview trimmed; stderr untouched;
	// exitCode preserved.
	resp := got[0]["response"].(map[string]any)
	stdout := resp["stdout"].(string)
	if len(stdout) >= len(huge) {
		t.Errorf("stdout not truncated: len=%d", len(stdout))
	}
	if !strings.Contains(stdout, "[truncated, original") {
		t.Errorf("missing truncation marker: %q", stdout[:80])
	}
	stdoutPrev := resp["stdoutPreview"].(string)
	if len(stdoutPrev) >= len(huge) {
		t.Errorf("stdoutPreview not truncated: len=%d", len(stdoutPrev))
	}
	if resp["stderr"].(string) != "short stderr" {
		t.Errorf("stderr modified: %q", resp["stderr"])
	}
	if resp["exitCode"].(float64) != 0 {
		t.Errorf("exitCode lost: %v", resp["exitCode"])
	}

	// Second action: nothing oversized → untouched (string response
	// doesn't have the keys we care about).
	if got[1]["response"].(string) != "tiny" {
		t.Errorf("untouched action got modified: %+v", got[1])
	}
}

// Empty or malformed input passes through unchanged — RunComplete must
// never refuse to record a run because the payload shape changed.
func TestTruncateActionsJSON_PassthroughOnNoActions(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte(``),
		[]byte(`[]`),
		[]byte(`not json`),        // malformed
		[]byte(`{"not":"array"}`), // unexpected shape
	}
	for _, in := range cases {
		got := truncateActionsJSON(in)
		if string(got) != string(in) {
			t.Errorf("input %q changed to %q", in, got)
		}
	}
}

// Below-threshold stdout/stderr round-trips unchanged. Specifically,
// we should NOT re-marshal and risk re-ordering keys when no field was
// actually modified.
func TestTruncateActionsJSON_NoChangeReturnsOriginal(t *testing.T) {
	in := []byte(`[{"type":"exec","response":{"stdout":"small","stderr":"also small"}}]`)
	got := truncateActionsJSON(in)
	if string(got) != string(in) {
		t.Errorf("input %q round-trip-modified to %q", in, got)
	}
}
