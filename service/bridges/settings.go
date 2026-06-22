package bridges

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/db/dbq"
)

// Settings is the user-tunable subset of bridge config exposed in the
// dashboard. Stored in bridges.settings JSONB. Distinct from
// bridges.config which carries driver-internal state.
//
// Owned by the bridges service so every reader (service mutations,
// trigger drivers, proto converter, sysagent tools) sees one source of
// truth.
type Settings struct {
	// WebAppEnabled controls whether a Telegram bridge registers a
	// persistent "Open" menu button that launches the agent's HTML UI
	// inside Telegram's in-app browser. When true (default), the bot's
	// default menu button is set to a web_app pointing at the agent
	// subdomain; auth happens automatically via initData verification.
	// When false, the menu button is reset to Telegram's default
	// commands menu. Only meaningful on telegram bridges.
	WebAppEnabled bool `json:"web_app_enabled"`
}

// DefaultSettings returns the settings a freshly created bridge row
// should carry. New bridges insert `{}` and rely on this function to
// materialize defaults at read time.
func DefaultSettings() Settings {
	return Settings{
		WebAppEnabled: true,
	}
}

// DecodeSettings parses a bridges.settings JSON blob, falling back to
// defaults for any missing keys. Empty / invalid JSON returns the
// default settings.
func DecodeSettings(raw []byte) Settings {
	s := DefaultSettings()
	if len(raw) == 0 {
		return s
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return s
	}
	if v, ok := m["web_app_enabled"]; ok {
		_ = json.Unmarshal(v, &s.WebAppEnabled)
	}
	return s
}

// Driver is the bot-platform adapter the bridges service calls when
// configuring or registering a bridge. trigger.TelegramDriver implements
// this. The interface lives here (not in trigger) so trigger can import
// this package for Settings without creating a cycle.
type Driver interface {
	GetMe(ctx context.Context, token string) (string, error)
	Init(ctx context.Context, br *dbq.Bridge) error
}
