package agentapi

import (
	"encoding/json"
	"fmt"
)

// truncateActionsJSON walks the actions array and trims any oversized
// stdout/stderr string field (per action) to ActionStringPreviewBytes,
// stamped with a [truncated, original N bytes] marker. Returns the
// rewritten bytes; on parse error it returns the input unchanged so a
// malformed payload never blocks a run from being marked complete.
//
// This is the authoritative gate for verbose stream-like fields in actions
// JSONB, including payloads from independently versioned agent containers.
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
			if truncateOversizeStringFields(req, ActionStringPreviewBytes) {
				changed = true
			}
		}
		if resp, _ := action["response"].(map[string]any); resp != nil {
			if truncateOversizeStringFields(resp, ActionStringPreviewBytes) {
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
