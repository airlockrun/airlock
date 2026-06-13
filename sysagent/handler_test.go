package sysagent

import "testing"

// TestUpgradeOutcomeRendering pins the prefix + source the LLM and the
// frontend bubble both rely on. The prefix is what tells the LLM the
// injected user-role message is a system event, not an operator
// statement; the source drives bubble styling.
func TestUpgradeOutcomeRendering(t *testing.T) {
	tests := []struct {
		status     string
		wantPrefix string
		wantSource string
	}{
		{"success", "[Upgrade succeeded] ", "upgrade"},
		{"error", "[Upgrade failed] ", "error"},
		{"refused", "[Request declined] ", "error"},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			prefix, source := upgradeOutcomeRendering(tt.status)
			if prefix != tt.wantPrefix {
				t.Errorf("prefix: got %q want %q", prefix, tt.wantPrefix)
			}
			if source != tt.wantSource {
				t.Errorf("source: got %q want %q", source, tt.wantSource)
			}
		})
	}
}

// TestUpgradeOutcomeRendering_UnknownStatus — the function falls through
// to a generic "[Upgrade <status>]" rather than swallowing the event.
// Better the LLM sees something it doesn't recognize than to drop the
// notification entirely.
func TestUpgradeOutcomeRendering_UnknownStatus(t *testing.T) {
	prefix, source := upgradeOutcomeRendering("queued")
	if prefix != "[Upgrade queued] " {
		t.Errorf("unknown status fallback prefix: got %q", prefix)
	}
	if source != "upgrade" {
		t.Errorf("unknown status fallback source: got %q want upgrade", source)
	}
}
