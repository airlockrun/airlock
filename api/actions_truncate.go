package api

import (
	"encoding/json"
	"fmt"
)

// truncateActionsJSON walks the actions array and trims any oversized
// stdout/stderr string field (per action) to ExecRecordPreviewBytes,
// stamped with a [truncated, original N bytes] marker. Returns the
// rewritten bytes; on parse error it returns the input unchanged so a
// malformed payload never blocks a run from being marked complete.
//
// Authoritative gate for actions JSONB size. The agent SDK already
// truncates per-call in agentsdk/exec.go before sending — this enforces
// the same invariant airlock-side so bypass scenarios (older SDK,
// hand-inserted rows from migrations, future bugs) can't land
// multi-MiB stdout in the audit log.
func truncateActionsJSON(actionsJSON []byte) []byte {
	if len(actionsJSON) == 0 {
		return actionsJSON
	}
	var actions []map[string]any
	if err := json.Unmarshal(actionsJSON, &actions); err != nil {
		// Not parseable as []action — leave it alone. The compactor
		// doesn't depend on shape either.
		return actionsJSON
	}
	changed := false
	for _, action := range actions {
		if req, _ := action["request"].(map[string]any); req != nil {
			if truncateOversizeStringFields(req, ExecRecordPreviewBytes) {
				changed = true
			}
		}
		if resp, _ := action["response"].(map[string]any); resp != nil {
			if truncateOversizeStringFields(resp, ExecRecordPreviewBytes) {
				changed = true
			}
		}
	}
	if !changed {
		return actionsJSON
	}
	out, err := json.Marshal(actions)
	if err != nil {
		return actionsJSON
	}
	return out
}

// truncateOversizeStringFields trims the four known oversize fields on
// a payload map. Returns true if any field was modified.
func truncateOversizeStringFields(m map[string]any, cap int) bool {
	if m == nil {
		return false
	}
	changed := false
	for _, key := range []string{"stdout", "stdoutPreview", "stderr", "stderrPreview"} {
		if v, ok := m[key].(string); ok && len(v) > cap {
			m[key] = v[:cap] + fmt.Sprintf("\n... [truncated, original %d bytes]\n", len(v))
			changed = true
		}
	}
	return changed
}
