package prompt

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/airlockrun/agentsdk"
)

// RenderExtras filters the agent's registered extra prompt fragments by
// the caller's resolved access and joins the visible ones with "\n\n".
// Returns an empty string when raw is unset or contains no visible specs.
func RenderExtras(raw []byte, access agentsdk.Access) string {
	if len(raw) == 0 {
		return ""
	}
	var specs []agentsdk.ExtraPromptSpec
	if err := json.Unmarshal(raw, &specs); err != nil {
		return ""
	}
	var parts []string
	for _, s := range specs {
		if len(s.Access) == 0 || slices.Contains(s.Access, access) {
			parts = append(parts, s.Text)
		}
	}
	return strings.Join(parts, "\n\n")
}
