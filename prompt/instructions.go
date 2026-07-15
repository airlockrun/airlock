package prompt

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/wire"
)

// RenderInstructions filters the agent's registered instruction fragments by
// the caller's resolved access and joins the visible ones with "\n\n".
// Returns an empty string when raw is unset or contains no visible specs.
func RenderInstructions(raw []byte, access agentsdk.Access) string {
	if len(raw) == 0 {
		return ""
	}
	var specs []wire.InstructionDef
	if err := json.Unmarshal(raw, &specs); err != nil {
		return ""
	}
	var parts []string
	for _, s := range specs {
		if len(s.Access) == 0 || slices.Contains(s.Access, wire.Access(access)) {
			parts = append(parts, s.Text)
		}
	}
	return strings.Join(parts, "\n\n")
}
