package bridges

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/db/dbq"
)

// DefaultPublicSessionTTLSeconds is the inactivity window after which a
// public bridge conversation is swept and finalized. Three hours covers
// the "user wandered off" case while keeping public state from
// accumulating indefinitely.
const DefaultPublicSessionTTLSeconds = 3 * 60 * 60

// DefaultPublicPromptTimeoutSeconds caps how long a single public-DM
// prompt run can take. Authenticated users get the full PromptHTTPCeiling;
// public callers are throttled tighter so a noisy abuser can't tie up the
// agent on long chains.
const DefaultPublicPromptTimeoutSeconds = 60

// PublicSessionMode controls how public conversations carry context
// across turns.
const (
	// PublicSessionModeSession persists turns in a per-channel conversation
	// (the default). The sweeper finalizes idle ones.
	PublicSessionModeSession = "session"

	// PublicSessionModeOneShot creates a fresh ephemeral conversation per
	// turn — no history loaded, conversation deleted immediately after the
	// run. If the user's message is a reply, the referenced text is
	// included as a wrapped context block so the LLM has at least the
	// thing being replied to.
	PublicSessionModeOneShot = "one_shot"
)

// Settings is the user-tunable subset of bridge config exposed in the
// dashboard. Stored in bridges.settings JSONB. Distinct from
// bridges.config which carries driver-internal state.
//
// Owned by the bridges service so every reader (service mutations,
// trigger drivers, proto converter, sysagent tools) sees one source of
// truth.
type Settings struct {
	// AllowPublicDMs lets unauthenticated users DM the bot at AccessPublic.
	// When false, unauth DMs are dropped (except /auth, which is the
	// linking opt-in path and always works).
	AllowPublicDMs bool `json:"allow_public_dms"`

	// PublicSessionTTLSeconds is the inactivity window before a public
	// conversation is finalized. 0 disables sweeping for that bridge.
	// Only meaningful when PublicSessionMode == "session".
	PublicSessionTTLSeconds int `json:"public_session_ttl_seconds"`

	// PublicSessionMode chooses between persistent ("session") and
	// stateless ("one_shot") public conversations. Defaults to session.
	PublicSessionMode string `json:"public_session_mode"`

	// PublicPromptTimeoutSeconds caps wall-clock duration of a single
	// public-DM prompt run. Authenticated users are not affected (they
	// run under the global PromptHTTPCeiling). 0 means "use the default"
	// (DefaultPublicPromptTimeoutSeconds).
	PublicPromptTimeoutSeconds int `json:"public_prompt_timeout_seconds"`
}

// DefaultSettings returns the settings a freshly created bridge row
// should carry. New bridges currently insert `{}` and rely on this
// function to materialize defaults at read time.
//
// AllowPublicDMs defaults to false: opening a bot to anonymous users is
// a deliberate operator choice (it exposes the agent's free-tier surface
// to the public internet). Operators flip it on from the bridge
// settings dialog when they actually want public access.
func DefaultSettings() Settings {
	return Settings{
		AllowPublicDMs:             false,
		PublicSessionTTLSeconds:    DefaultPublicSessionTTLSeconds,
		PublicSessionMode:          PublicSessionModeSession,
		PublicPromptTimeoutSeconds: DefaultPublicPromptTimeoutSeconds,
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
	if v, ok := m["allow_public_dms"]; ok {
		_ = json.Unmarshal(v, &s.AllowPublicDMs)
	}
	if v, ok := m["public_session_ttl_seconds"]; ok {
		_ = json.Unmarshal(v, &s.PublicSessionTTLSeconds)
	}
	if v, ok := m["public_session_mode"]; ok {
		_ = json.Unmarshal(v, &s.PublicSessionMode)
	}
	if s.PublicSessionMode != PublicSessionModeOneShot {
		s.PublicSessionMode = PublicSessionModeSession
	}
	if v, ok := m["public_prompt_timeout_seconds"]; ok {
		_ = json.Unmarshal(v, &s.PublicPromptTimeoutSeconds)
	}
	if s.PublicPromptTimeoutSeconds <= 0 {
		s.PublicPromptTimeoutSeconds = DefaultPublicPromptTimeoutSeconds
	}
	return s
}

// Driver is the bot-platform adapter the bridges service calls when
// configuring or registering a bridge. trigger.TelegramDriver and
// trigger.DiscordDriver implement this. The interface lives here (not
// in trigger) so trigger can import this package for Settings without
// creating a cycle.
type Driver interface {
	GetMe(ctx context.Context, token string) (string, error)
	Init(ctx context.Context, br *dbq.Bridge) error
}
