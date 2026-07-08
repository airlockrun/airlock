package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// pickConfirmationBody chooses the best human-readable body string from a
// PermissionAsked metadata bag for display in a bridge driver's
// confirmation prompt. Producers vary in what they stuff in:
//   - agentsdk run_js puts the JS source under "code".
//   - sysagent destructive tools put the raw JSON args under "args".
//   - doom_loop carries a human "message".
//
// Whichever is present (in this priority order) becomes the body. The
// driver wraps the return as a <pre>...</pre> block; empty string means
// the driver shows just the permission name with no body.
func pickConfirmationBody(m map[string]any) string {
	if c, ok := m["code"].(string); ok && c != "" {
		return c
	}
	if a, ok := m["args"].(string); ok && a != "" {
		// Pretty-print when the args look like JSON — sysagent's executor
		// puts a single-line string in; multi-line is much more readable in
		// chat. Fall back to the raw string on parse failure.
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, []byte(a), "", "  "); err == nil && pretty.Len() > 0 {
			return pretty.String()
		}
		return a
	}
	if msg, ok := m["message"].(string); ok && msg != "" {
		return msg
	}
	return ""
}

// ResponseEvent represents an NDJSON event from the agent response stream,
// forwarded to the bridge driver for progressive delivery.
type ResponseEvent struct {
	Type       string // "run_started", "text-delta", "tool-call", "tool-result", "confirmation_required", "info"
	Text       string // for text-delta / info: the delta text or info message
	ToolCallID string // for tool_call/tool_result
	ToolName   string // for tool_call/tool_result
	ToolInput  string // for tool_call: the tool arguments
	ToolOutput string // for tool_result: the tool output
	ToolError  string // for tool_result: error message if failed
	Raw        []byte // full NDJSON line (for non-text events drivers may need)

	// Populated when Type == "run_started" or "confirmation_required":
	RunID      string
	Permission string
	Patterns   []string
	Code       string
	// Description is the plain-language summary a run_js confirmation carries;
	// drivers lead with it instead of the permission name when present.
	Description string
}

// CancelButtonAfter is how long a bridge run can stream before the driver
// posts a "Still working… Tap to stop" message with a cancel button. The
// message is deleted when the run ends (naturally or via the user tap).
const CancelButtonAfter = 20 * time.Second

// BridgeCallback represents an interactive UI acknowledgement — a button tap
// on an inline keyboard or similar platform-native affordance. Drivers that
// don't support rich UI leave this nil.
type BridgeCallback struct {
	Data      string // opaque payload, e.g. "approve:<runID>"
	AckID     string // platform-specific ack handle (Telegram callback_query.id)
	MessageID string // ID of the message the button is attached to (so we
	// can edit/strip it once the user has acted on it)
}

// BridgeEvent represents a normalized incoming event from any platform.
// Either Text/Files (new user message) or Callback (button tap) is populated.
type BridgeEvent struct {
	BridgeID          uuid.UUID
	ExternalID        string // platform chat_id (Telegram chat ID, etc.)
	SenderID          string // platform user ID of sender (for identity lookup)
	SenderName        string
	Text              string
	Files             []BridgeFile // attached files (photos, documents)
	Callback          *BridgeCallback
	ReferencedMessage *BridgeReferencedMessage // reply target / forward source (driver-populated)
	ManagedBot        *ManagedBotEvent         // Telegram managed_bot_created service message (manager bridges only)
	RawPayload        []byte
}

// ManagedBotEvent carries a Telegram `managed_bot_created` service message —
// a new bot a user created via the manager bot's deep-link flow. Only a
// manager bridge (is_manager) produces these; HandleEvent turns it into a
// bridge for the freshly-created bot.
type ManagedBotEvent struct {
	BotID    int64
	Username string
	// ExternalID is the chat the creation happened in — the exact account +
	// device whose client just went through the flow. It's the unambiguous
	// reply target for the post-create deep link (no platform_identities
	// lookup, so a user with multiple linked Telegram accounts is a non-issue).
	ExternalID string
	// SenderID is the Telegram user who created the bot (optional sanity check
	// against the session owner's linked identities).
	SenderID string
}

// BridgeReferenceKind distinguishes the platform mechanism that produced
// the reference so the prompt builder can label it for the LLM.
const (
	// BridgeReferenceReply — the user replied to another message
	// (Telegram reply_to_message).
	BridgeReferenceReply = "reply"
	// BridgeReferenceForward — the user forwarded a message authored
	// elsewhere (Telegram forward_origin).
	BridgeReferenceForward = "forward"
)

// BridgeReferencedMessage describes a message the current event points
// at — either a reply target or a forwarded message. Surfaced to the
// LLM as a wrapped context block regardless of session mode, so the
// model has the referenced content even when it's outside the active
// conversation history (or when there is no history at all).
type BridgeReferencedMessage struct {
	Kind       string // BridgeReferenceReply | BridgeReferenceForward
	SenderName string // author of the referenced content
	Text       string
	AuthoredAt time.Time
	FromBot    bool // true when the referenced message was authored by our bot (replies only)
}

// BridgeFile is a file attached to a bridge message.
type BridgeFile struct {
	FileID      string // platform file ID (e.g. Telegram file_id)
	Filename    string
	ContentType string
	Size        int64
	Data        []byte // file content (downloaded by driver)

	// IsVoiceNote marks a short voice recording (e.g. Telegram "voice")
	// that the bridge layer should auto-transcribe before forwarding to
	// the agent. Plain audio/video/document attachments leave this false.
	IsVoiceNote bool
}

// BridgeDriver handles platform-specific message parsing and delivery.
type BridgeDriver interface {
	// Init is called once when a bridge is first created.
	// Uses pointer so the driver can set initial config (e.g. poll offset).
	Init(ctx context.Context, br *dbq.Bridge) error

	// Activate is called on every startup for active bridges.
	Activate(ctx context.Context, br dbq.Bridge) error

	// Teardown is called when a bridge is deleted or disabled.
	Teardown(ctx context.Context, br dbq.Bridge) error

	// Poll fetches new events from the platform.
	// Uses pointer so the driver can update br.Config (e.g. poll offset).
	Poll(ctx context.Context, br *dbq.Bridge) ([]BridgeEvent, error)

	// SendStream delivers a response, streaming text deltas as they arrive.
	// echo controls whether tool-call / tool-result bubbles are rendered;
	// drivers that collapse tool output some other way may ignore it.
	// Returns the final assembled text.
	SendStream(ctx context.Context, br dbq.Bridge, externalID string, echo bool, events <-chan ResponseEvent) (string, error)

	// DefaultEcho returns whether tool bubbles render by default on this
	// platform. Drivers that display each tool-call/tool-result as its own
	// chat message (Telegram) should return false; drivers whose UI can
	// collapse tool output inline (web) should return true.
	// Used when a conversation has no explicit settings.echo override.
	DefaultEcho() bool

	// RemoveButtons strips the inline keyboard / component buttons from a
	// previously sent message, leaving its text intact. Called after the
	// user taps an approve/deny button so the resolved confirmation can't
	// be tapped again. Best-effort: errors are logged but not propagated.
	RemoveButtons(ctx context.Context, br dbq.Bridge, externalID, messageID string) error
}

// CommandRegistrar is an optional BridgeDriver capability: platforms with
// a native command menu (Telegram setMyCommands) implement it to receive
// the slash-command registry on activation.
// Drivers without such a menu simply don't implement it.
type CommandRegistrar interface {
	RegisterCommands(ctx context.Context, br dbq.Bridge, cmds []SlashCommand) error
}

// BridgeManager manages bridge drivers and routes events to agents.
type BridgeManager struct {
	drivers      map[string]BridgeDriver
	prompter     *PromptProxy
	db           *db.DB
	encryptor    secrets.Store
	logger       *zap.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	hmacSecret   string                   // for generating identity-linking URLs
	publicURL    string                   // base URL for identity-linking URLs
	agentBaseURL func(slug string) string // builds {scheme}://{slug}.{agentDomain}[:port]; required for Telegram web-app menu button

	// pollers tracks the running poller for each bridge ID. Needed so
	// RemoveBridge can stop exactly one poller on bridge deletion —
	// without it, a deleted bridge's goroutine would keep calling
	// getUpdates on the same bot token. If the user then recreates the
	// bridge with the same token, two pollers race for the token and
	// Telegram returns 409 Conflict on both.
	//
	// Value is *pollerHandle (not bare CancelFunc) so the goroutine's
	// self-cleanup can identify *its own* entry by comparing the unique
	// pollCtx pointer. Comparing CancelFunc values via reflect.Pointer
	// returns the closure's code address, which is identical for every
	// CancelFunc returned by context.WithCancel — so an old goroutine's
	// defer would falsely match the entry of a *replacement* poller and
	// delete it from the map, leaking the replacement and stacking
	// duplicate pollers on every subsequent AddBridge call.
	pollersMu sync.Mutex
	pollers   map[uuid.UUID]*pollerHandle

	// sysagent is the in-airlock system-agent runtime. Routes inbound
	// DMs on system bridges (br.IsSystem) into a per-bridge sysagent
	// thread. Nil until AttachSysagent wires it after sysagent.New
	// completes (constructor order: BridgeManager precedes the router,
	// the router builds sysagent). System bridges receiving an event
	// before AttachSysagent runs will silently drop, which is fine —
	// inbound DMs can't arrive until the bridge poller is running, and
	// pollers only start after airlock.Start which is well past
	// AttachSysagent.
	sysagent SysagentRuntime

	// managedBotIngest turns a Telegram `managed_bot_created` event (seen on
	// a manager bridge's poll loop) into a new bridge for the freshly-created
	// bot. Wired to bridges.Service.IngestManagedBotCreated via
	// AttachManagedBotIngest — a callback (not a direct dep) because the
	// bridges service already holds *BridgeManager, so a direct reference
	// would be a cycle. Nil until wired; a managed_bot_created before then is
	// dropped (managed bridges only start polling after wiring).
	managedBotIngest func(ctx context.Context, managerToken string, botUserID int64, botUsername string) (string, error)
}

// AttachSysagent wires the sysagent runtime after the router has built
// it. Idempotent; the last set wins.
func (m *BridgeManager) AttachSysagent(s SysagentRuntime) {
	m.sysagent = s
}

// AttachManagedBotIngest wires the managed-bot ingest callback (see the
// field doc). Idempotent; the last set wins.
func (m *BridgeManager) AttachManagedBotIngest(fn func(ctx context.Context, managerToken string, botUserID int64, botUsername string) (string, error)) {
	m.managedBotIngest = fn
}

// pollerHandle pairs a poller goroutine's cancel func with its context.
// The context pointer is the per-instance identity used by the goroutine's
// defer block to confirm "this is my entry" before removing it from the
// map.
type pollerHandle struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewBridgeManager creates a BridgeManager. agentBaseURL builds the
// external URL for an agent's subdomain ({scheme}://{slug}.{domain}[:port]);
// the Telegram driver needs it to register the web-app menu button.
func NewBridgeManager(drivers map[string]BridgeDriver, prompter *PromptProxy, database *db.DB, encryptor secrets.Store, hmacSecret, publicURL string, agentBaseURL func(slug string) string, logger *zap.Logger) *BridgeManager {
	if agentBaseURL == nil {
		panic("trigger: NewBridgeManager called with nil agentBaseURL")
	}
	return &BridgeManager{
		drivers:      drivers,
		prompter:     prompter,
		db:           database,
		encryptor:    encryptor,
		hmacSecret:   hmacSecret,
		publicURL:    publicURL,
		agentBaseURL: agentBaseURL,
		logger:       logger,
		pollers:      make(map[uuid.UUID]*pollerHandle),
	}
}

// Start sets up all active bridges and starts pollers.
func (m *BridgeManager) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.ctx = ctx

	q := dbq.New(m.db.Pool())

	bridges, err := q.ListActiveBridges(ctx)
	if err != nil {
		return fmt.Errorf("list active bridges: %w", err)
	}

	for _, br := range bridges {
		driver, ok := m.drivers[br.Type]
		if !ok {
			m.logger.Warn("no driver for bridge type", zap.String("type", br.Type))
			continue
		}

		// Decrypt token for driver setup.
		decrypted := br
		if br.BotTokenRef != "" {
			token, err := m.encryptor.Get(ctx, "bridge/"+pgUUID(br.ID).String()+"/bot_token", br.BotTokenRef)
			if err != nil {
				m.logger.Error("decrypt bridge token failed",
					zap.String("name", br.Name),
					zap.Error(err))
				continue
			}
			decrypted.BotTokenRef = token
		}

		if err := driver.Activate(ctx, decrypted); err != nil {
			m.logger.Error("bridge activate failed",
				zap.String("name", br.Name),
				zap.Error(err))
			continue
		}
		m.registerCommands(ctx, driver, decrypted)
		if !decrypted.AgentID.Valid {
			m.clearWebAppMenuButton(ctx, driver, decrypted)
		} else {
			m.syncWebAppMenuButton(ctx, driver, decrypted)
		}
		m.startPoller(ctx, decrypted)
	}

	m.logger.Info("bridge manager started", zap.Int("pollers", len(bridges)))
	return nil
}

// expectedWebAppMenuURL returns the Telegram Web App URL for an agent-bound
// bridge. The URL opens the agent subdomain bootstrap path that verifies
// Telegram initData and issues an agent-subdomain session cookie.
func (m *BridgeManager) expectedWebAppMenuURL(ctx context.Context, br dbq.Bridge) (string, bool) {
	if br.Type != "telegram" || !br.AgentID.Valid {
		return "", false
	}
	q := dbq.New(m.db.Pool())
	agent, err := q.GetAgentByID(ctx, br.AgentID)
	if err != nil {
		m.logger.Warn("web-app menu button: agent lookup failed",
			zap.String("bridge", br.Name),
			zap.Error(err))
		return "", false
	}
	return m.agentBaseURL(agent.Slug) + "/__air/tg/start?b=" + pgUUID(br.ID).String(), true
}

// syncWebAppMenuButton converges a Telegram bridge's persistent chat menu
// button to the expected agent Web App URL. It reads Telegram state first and
// only writes when the URL is absent or stale. Managed bridges skip this during
// AddBridge because Telegram clients can race immediately after bot creation;
// /start and reconciliation still repair the button.
func (m *BridgeManager) syncWebAppMenuButton(ctx context.Context, driver BridgeDriver, br dbq.Bridge) {
	url, ok := m.expectedWebAppMenuURL(ctx, br)
	if !ok {
		return
	}
	tg, ok := driver.(*TelegramDriver)
	if !ok {
		return
	}
	button, err := tg.GetMenuButton(ctx, br.BotTokenRef)
	if err != nil {
		m.logger.Warn("web-app menu button: getChatMenuButton failed",
			zap.String("bridge", br.Name),
			zap.Error(err))
		return
	}
	if button.Type == "web_app" && button.WebAppURL == url {
		return
	}
	if err := tg.SetMenuButton(ctx, br.BotTokenRef, url); err != nil {
		m.logger.Warn("web-app menu button: setChatMenuButton failed",
			zap.String("bridge", br.Name),
			zap.String("url", url),
			zap.Error(err))
		return
	}
	m.logger.Info("web-app menu button registered",
		zap.String("bridge", br.Name),
		zap.String("url", url))
}

// clearWebAppMenuButton resets the Telegram menu button when a bridge no
// longer targets an agent. Telegram stores the button server-side, so Airlock
// must clear it when a bridge is rebound to system/unbound use.
func (m *BridgeManager) clearWebAppMenuButton(ctx context.Context, driver BridgeDriver, br dbq.Bridge) {
	if br.Type != "telegram" {
		return
	}
	tg, ok := driver.(*TelegramDriver)
	if !ok {
		return
	}
	button, err := tg.GetMenuButton(ctx, br.BotTokenRef)
	if err != nil {
		m.logger.Warn("web-app menu button: getChatMenuButton failed before clear",
			zap.String("bridge", br.Name),
			zap.Error(err))
		// A default write is safe and ensures stale state is cleared when the
		// read path is unavailable but setChatMenuButton still works.
	}
	if err == nil && button.Type != "web_app" {
		return
	}
	if err := tg.SetMenuButton(ctx, br.BotTokenRef, ""); err != nil {
		m.logger.Warn("web-app menu button: clear failed",
			zap.String("bridge", br.Name),
			zap.Error(err))
		return
	}
	m.logger.Info("web-app menu button cleared", zap.String("bridge", br.Name))
}

// registerCommands pushes the slash-command registry to drivers that
// implement CommandRegistrar. Failures are logged but non-fatal — the
// platform command menu is a convenience; commands still dispatch via
// TrySlashCommand without it.
func (m *BridgeManager) registerCommands(ctx context.Context, driver BridgeDriver, br dbq.Bridge) {
	r, ok := driver.(CommandRegistrar)
	if !ok {
		return
	}
	if err := r.RegisterCommands(ctx, br, Registry); err != nil {
		m.logger.Warn("register commands failed",
			zap.String("bridge", br.Name),
			zap.Error(err))
	}
}

// AddBridge activates a newly created bridge and starts its poller.
// Idempotent: if a poller is already running for this bridge ID (e.g. the
// bridge was re-registered after a config change), the existing one is
// cancelled first so only one poller hits the platform at a time.
func (m *BridgeManager) AddBridge(bridgeID uuid.UUID) {
	if m.ctx == nil {
		return
	}
	q := dbq.New(m.db.Pool())
	br, err := q.GetBridgeByID(m.ctx, toPgUUID(bridgeID))
	if err != nil {
		m.logger.Error("add bridge: get bridge", zap.Error(err))
		return
	}
	driver, ok := m.drivers[br.Type]
	if !ok {
		return
	}
	token, err := m.encryptor.Get(m.ctx, "bridge/"+pgUUID(br.ID).String()+"/bot_token", br.BotTokenRef)
	if err != nil {
		m.logger.Error("add bridge: decrypt token", zap.Error(err))
		return
	}
	br.BotTokenRef = token
	if err := driver.Activate(m.ctx, br); err != nil {
		m.logger.Error("add bridge: activate", zap.Error(err))
		return
	}
	m.registerCommands(m.ctx, driver, br)
	if !br.AgentID.Valid {
		m.clearWebAppMenuButton(m.ctx, driver, br)
	} else if !br.Managed {
		m.syncWebAppMenuButton(m.ctx, driver, br)
	}
	// Stop any stale poller for the same bridge ID before starting a new one.
	m.cancelPoller(bridgeID)
	m.startPoller(m.ctx, br)
}

// RemoveBridge stops the poller for a bridge. Safe to call for an unknown
// bridge ID — it's a no-op. The DB row is NOT touched here; callers that
// want full deletion do the DB work separately (typically by calling
// q.DeleteBridge alongside this).
func (m *BridgeManager) RemoveBridge(bridgeID uuid.UUID) {
	m.cancelPoller(bridgeID)
}

// TeardownBridge runs the driver's teardown for a bridge — for Telegram this
// clears the chat menu button so a deleted/disabled bridge doesn't leave a
// dead web-app "Open" button behind. Best-effort: it logs and returns on lookup/decrypt/teardown
// failure so it never blocks an agent or bridge deletion. Call it BEFORE the
// bridge row is deleted and before RemoveBridge, while the bot token is still
// resolvable. Uses the manager's own context so the platform API call isn't
// cut short when the deleting request returns.
func (m *BridgeManager) TeardownBridge(bridgeID uuid.UUID) {
	if m.ctx == nil {
		return
	}
	q := dbq.New(m.db.Pool())
	br, err := q.GetBridgeByID(m.ctx, toPgUUID(bridgeID))
	if err != nil {
		m.logger.Warn("teardown bridge: get bridge", zap.Error(err))
		return
	}
	driver, ok := m.drivers[br.Type]
	if !ok {
		return
	}
	if br.BotTokenRef != "" {
		token, err := m.encryptor.Get(m.ctx, "bridge/"+pgUUID(br.ID).String()+"/bot_token", br.BotTokenRef)
		if err != nil {
			m.logger.Warn("teardown bridge: decrypt token", zap.String("name", br.Name), zap.Error(err))
			return
		}
		br.BotTokenRef = token
	}
	if err := driver.Teardown(m.ctx, br); err != nil {
		m.logger.Warn("teardown bridge: driver teardown", zap.String("name", br.Name), zap.Error(err))
	}
}

// RemoveBridgesByOwner stops every poller for bridges owned by a
// specific user. Called from service/users.Delete BEFORE the DB
// CASCADE removes the bridge rows — otherwise the poller goroutines
// would keep calling getUpdates against now-deleted bridges until
// their next transient failure, racing on the bot token with any
// replacement bridge that happened to land on the same row id.
func (m *BridgeManager) RemoveBridgesByOwner(ctx context.Context, ownerID uuid.UUID) error {
	q := dbq.New(m.db.Pool())
	rows, err := q.ListBridgesByOwner(ctx, pgtype.UUID{Bytes: ownerID, Valid: true})
	if err != nil {
		return fmt.Errorf("list bridges by owner: %w", err)
	}
	for _, id := range rows {
		m.cancelPoller(uuid.UUID(id.Bytes))
	}
	return nil
}

// cancelPoller stops the poller goroutine for a specific bridge ID, if any.
// Holds pollersMu while swapping/deleting so concurrent AddBridge+RemoveBridge
// calls can't race on the map.
func (m *BridgeManager) cancelPoller(bridgeID uuid.UUID) {
	m.pollersMu.Lock()
	h, ok := m.pollers[bridgeID]
	delete(m.pollers, bridgeID)
	m.pollersMu.Unlock()
	if ok {
		h.cancel()
	}
}

// Stop gracefully shuts down all pollers.
func (m *BridgeManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

// BotTokenForBridge returns the decrypted Telegram bot token for
// (agentID, bridgeID) — only if the bridge belongs to that agent and is
// of type "telegram". The agent guard is the cross-agent boundary at the
// lookup layer; HMAC verification of the caller's initData then gates
// the actual auth. Returns an error on any mismatch so the caller can
// 401 without leaking which constraint failed.
//
// Used by the airlock proxy's Telegram Web App auth handler.
func (m *BridgeManager) BotTokenForBridge(ctx context.Context, agentID, bridgeID uuid.UUID) (string, error) {
	q := dbq.New(m.db.Pool())
	br, err := q.GetBridgeByID(ctx, toPgUUID(bridgeID))
	if err != nil {
		return "", fmt.Errorf("get bridge: %w", err)
	}
	if br.Type != "telegram" {
		return "", fmt.Errorf("bridge %s is not telegram", bridgeID)
	}
	if !br.AgentID.Valid || uuid.UUID(br.AgentID.Bytes) != agentID {
		return "", fmt.Errorf("bridge %s does not belong to agent %s", bridgeID, agentID)
	}
	if br.BotTokenRef == "" {
		return "", fmt.Errorf("bridge %s has no bot token", bridgeID)
	}
	token, err := m.encryptor.Get(ctx, "bridge/"+pgUUID(br.ID).String()+"/bot_token", br.BotTokenRef)
	if err != nil {
		return "", fmt.Errorf("decrypt bridge token: %w", err)
	}
	return token, nil
}

// isCancelTap reports whether a bridge event is a "Stop" button tap.
// These are routed past the serial event worker (see startPoller) so a
// cancel can reach a run that is still in flight.
func isCancelTap(e BridgeEvent) bool {
	return e.Callback != nil && strings.HasPrefix(e.Callback.Data, "cancel:")
}

// HandleEvent processes a parsed BridgeEvent — routes to agent via PromptProxy.
func (m *BridgeManager) HandleEvent(ctx context.Context, event BridgeEvent) error {
	q := dbq.New(m.db.Pool())
	br, err := q.GetBridgeByID(ctx, toPgUUID(event.BridgeID))
	if err != nil {
		return fmt.Errorf("get bridge: %w", err)
	}

	// Decrypt token once up front — needed by both system-bridge and
	// agent-bridge paths for SendText / SendStream / AnswerCallback.
	if br.BotTokenRef != "" {
		token, derr := m.encryptor.Get(ctx, "bridge/"+pgUUID(br.ID).String()+"/bot_token", br.BotTokenRef)
		if derr != nil {
			return fmt.Errorf("decrypt bridge token: %w", derr)
		}
		br.BotTokenRef = token
	}

	// Managed-bot creation arrives only on a manager bridge. Routed before
	// the system/agent branches so a system+manager bridge handles both DMs
	// and managed_bot_created on the same poll loop. br.BotTokenRef is the
	// decrypted manager token.
	if event.ManagedBot != nil {
		if !br.IsManager {
			return nil // stray service message on a non-manager bridge — ignore
		}
		return m.handleManagerBotCreated(ctx, br, *event.ManagedBot)
	}

	if br.IsSystem {
		return m.handleSystemBridgeEvent(ctx, br, event)
	}

	if !br.AgentID.Valid {
		return nil // orphan bridge (agent deleted, not system) — drop until rebinding
	}
	agentID := pgUUID(br.AgentID)

	driver := m.drivers[br.Type]

	// Cancel button tap (driver posts "Stop" button after CancelButtonAfter).
	// Distinct from approve/deny callbacks routed through HandleCallback —
	// those resolve a *suspended* run, this aborts a *running* one.
	if isCancelTap(event) {
		runIDStr := strings.TrimPrefix(event.Callback.Data, "cancel:")
		if runID, err := uuid.Parse(runIDStr); err == nil {
			m.prompter.dispatcher.CancelRun(runID)
		}
		// Telegram needs an explicit ack to clear the spinner.
		if tg, ok := driver.(*TelegramDriver); ok && event.Callback.AckID != "" {
			_ = tg.AnswerCallbackQuery(ctx, br.BotTokenRef, event.Callback.AckID, "Cancelled")
		}
		return nil
	}

	// /auth runs before identity lookup so unlinked users can opt in
	// explicitly. We deliberately don't auto-DM the link on every
	// unrecognized sender — the bridge may serve public-access agents
	// where most users never need to link, and unsolicited DMs are
	// noise.
	if isAuthCommand(event.Text) {
		return m.handleAuthCommand(ctx, br, driver, event)
	}

	// Resolve user_id from platform identity. Lookup failure means the
	// sender hasn't run /auth — bridge chat requires a linked identity, so
	// we silently drop. (/auth itself ran above, before this gate.)
	identity, idErr := q.GetPlatformIdentity(ctx, dbq.GetPlatformIdentityParams{
		Platform:       br.Type,
		PlatformUserID: event.SenderID,
	})
	if idErr != nil {
		if isStartCommand(event.Text) {
			return m.handleAuthCommand(ctx, br, driver, event)
		}
		m.logger.Debug("dropping unlinked sender (bridge requires a linked identity)",
			zap.String("bridge", br.Name),
			zap.String("sender_id", event.SenderID),
		)
		return nil
	}
	userID := pgUUID(identity.UserID)
	if isStartCommand(event.Text) {
		m.syncWebAppMenuButton(ctx, driver, br)
	}

	// Resolve effective echo for this conversation from the user's
	// per-channel override, falling back to the driver default.
	echo := driver.DefaultEcho()
	if conv, err := q.GetConversationBySource(ctx, dbq.GetConversationBySourceParams{
		AgentID: toPgUUID(agentID),
		UserID:  toPgUUID(userID),
		Source:  "bridge",
	}); err == nil {
		echo = ResolveEcho(conv.Settings, driver.DefaultEcho())
	}

	// Create event channel for streaming between PromptProxy and driver.
	respEvents := make(chan ResponseEvent, 64)

	// Start driver streaming in background.
	var driverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, driverErr = driver.SendStream(ctx, br, event.ExternalID, echo, respEvents)
	}()

	// Branch: UI callback (button tap) vs new user message.
	if event.Callback != nil {
		// Strip the buttons off the original message so the user can't
		// re-tap a resolved confirmation. Best-effort, fire-and-forget.
		if event.Callback.MessageID != "" {
			if err := driver.RemoveButtons(ctx, br, event.ExternalID, event.Callback.MessageID); err != nil {
				m.logger.Debug("remove buttons failed",
					zap.String("bridge", br.Name),
					zap.String("message_id", event.Callback.MessageID),
					zap.Error(err))
			}
		}
		_, cbErr := m.prompter.HandleCallback(ctx, agentID, event.BridgeID, userID, event.ExternalID, event.Callback.Data, respEvents)
		// Wait for driver to finish rendering anything queued before we ack.
		wg.Wait()
		// Ack the tap so Telegram clears its loading spinner. Failure is
		// non-fatal — the spinner just expires after ~15s.
		if tg, ok := driver.(*TelegramDriver); ok && event.Callback.AckID != "" {
			_ = tg.AnswerCallbackQuery(ctx, br.BotTokenRef, event.Callback.AckID, "")
		}
		if driverErr != nil {
			m.logger.Error("send stream failed",
				zap.String("bridge", br.Name),
				zap.Error(driverErr))
		}
		if cbErr != nil {
			return fmt.Errorf("prompt proxy (callback): %w", cbErr)
		}
		return nil
	}

	// Route to prompt proxy — streams events into the channel.
	_, err = m.prompter.HandleMessage(ctx, agentID, event.BridgeID, userID, event.ExternalID, true, event.Text, event.Files, event.ReferencedMessage, respEvents)
	if err != nil {
		return fmt.Errorf("prompt proxy: %w", err)
	}

	// Wait for driver to finish delivering.
	wg.Wait()
	if driverErr != nil {
		m.logger.Error("send stream failed",
			zap.String("bridge", br.Name),
			zap.Error(driverErr))
	}

	return nil
}

// isAuthCommand reports whether text is the /auth slash command,
// possibly with arguments. /auth is special-cased above identity lookup
// so unlinked users can invoke it.
func isAuthCommand(text string) bool {
	t := strings.ToLower(strings.TrimSpace(text))
	return t == "/auth" || strings.HasPrefix(t, "/auth ")
}

// handleAuthCommand replies to /auth with a fresh signed linking URL.
// Telegram bots are in DMs already, so the link is delivered straight back
// to the sender's chat.
func (m *BridgeManager) handleAuthCommand(ctx context.Context, br dbq.Bridge, driver BridgeDriver, event BridgeEvent) error {
	if m.publicURL == "" {
		return nil
	}
	linkURL := buildAuthExternalURL(m.publicURL, m.hmacSecret, br.Type, pgUUID(br.ID).String(), event.SenderID)
	msg := fmt.Sprintf("Click to link your Airlock account:\n%s", linkURL)
	if dr, ok := driver.(*TelegramDriver); ok {
		chatID, _ := strconv.ParseInt(event.ExternalID, 10, 64)
		if chatID == 0 {
			return nil
		}
		return dr.SendMessage(ctx, br.BotTokenRef, chatID, msg)
	}
	return nil
}

// buildAuthExternalURL generates an HMAC-signed URL for identity linking.
// The bridgeID is bound into the HMAC payload so the preview endpoint can
// look up the originating bridge (for bot username + live user lookup) while
// still rejecting tampering. A bridge-scoped link also means an attacker who
// somehow obtained one can't repoint it at a different bot.
func buildAuthExternalURL(publicURL, hmacSecret, platform, bridgeID, platformUserID string) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := platform + ":" + bridgeID + ":" + platformUserID + ":" + ts
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s/auth-external?platform=%s&bridge=%s&uid=%s&ts=%s&sig=%s",
		publicURL, platform, bridgeID, platformUserID, ts, sig)
}

// SendParts sends display parts to a bridge conversation.
// Looks up the bridge, decrypts the token, and delegates to the driver.
func (m *BridgeManager) SendParts(ctx context.Context, bridgeID uuid.UUID, externalID string, parts []agentsdk.DisplayPart) error {
	q := dbq.New(m.db.Pool())
	br, err := q.GetBridgeByID(ctx, toPgUUID(bridgeID))
	if err != nil {
		return fmt.Errorf("get bridge: %w", err)
	}

	token, err := m.encryptor.Get(ctx, "bridge/"+pgUUID(br.ID).String()+"/bot_token", br.BotTokenRef)
	if err != nil {
		return fmt.Errorf("decrypt token: %w", err)
	}

	driver, ok := m.drivers[br.Type]
	if !ok {
		return fmt.Errorf("no driver for type %q", br.Type)
	}

	if dr, ok := driver.(*TelegramDriver); ok {
		chatID, err := strconv.ParseInt(externalID, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid chat ID: %w", err)
		}
		return dr.SendParts(ctx, token, chatID, parts)
	}

	return fmt.Errorf("driver %q does not support SendParts", br.Type)
}

// SendMessage sends a text message to a bridge conversation. Convenience wrapper.
func (m *BridgeManager) SendMessage(ctx context.Context, bridgeID uuid.UUID, externalID, text string) error {
	return m.SendParts(ctx, bridgeID, externalID, []agentsdk.DisplayPart{{Type: "text", Text: text}})
}

// StreamToBridge is the single bridge-delivery primitive the completion-resume
// paths share: it resolves the bridge's driver + echo setting and streams a
// ResponseEvent channel to the chat via SendStream. The caller produces the
// events from whatever run source it has and closes the channel — an in-process
// sysagent run via bridgeSink (BridgeManager.ResumeSystemConversation), or an
// agent NDJSON stream via StreamNDJSONResponse (api NotifyUpgradeComplete).
// Because both go through SendStream, text, tool calls, and — crucially —
// confirmation_required prompts render identically; a gated tool the resume
// chains into gets Approve/Reject buttons instead of being silently swallowed.
//
// settingsJSON is the conversation's settings blob (drives the per-thread echo
// override). On a resolution error the channel is drained so the producer
// goroutine never blocks on a full buffer.
func (m *BridgeManager) StreamToBridge(ctx context.Context, bridgeID uuid.UUID, externalID string, settingsJSON []byte, events <-chan ResponseEvent) error {
	q := dbq.New(m.db.Pool())
	br, err := q.GetBridgeByID(ctx, toPgUUID(bridgeID))
	if err != nil {
		for range events {
		}
		return fmt.Errorf("get bridge: %w", err)
	}
	// SendStream uses br.BotTokenRef as the literal bot token. The poll loop
	// swaps the ciphertext ref for the decrypted token in its in-memory copy;
	// a fresh DB row still carries the ref, so decrypt it here or Telegram sees
	// /bot<ciphertext>/... and 404s.
	if br.BotTokenRef != "" {
		token, derr := m.encryptor.Get(ctx, "bridge/"+pgUUID(br.ID).String()+"/bot_token", br.BotTokenRef)
		if derr != nil {
			for range events {
			}
			return fmt.Errorf("decrypt bot token: %w", derr)
		}
		br.BotTokenRef = token
	}
	driver, ok := m.drivers[br.Type]
	if !ok {
		for range events {
		}
		return fmt.Errorf("no driver for type %q", br.Type)
	}
	echo := ResolveEcho(settingsJSON, driver.DefaultEcho())
	_, err = driver.SendStream(ctx, br, externalID, echo, events)
	return err
}

// startPoller starts a background goroutine that polls a bridge for new events.
// The goroutine's context is scoped to this bridge ID so RemoveBridge /
// AddBridge-on-same-id can stop exactly one poller without tearing down
// others.
func (m *BridgeManager) startPoller(parent context.Context, br dbq.Bridge) {
	pollCtx, cancel := context.WithCancel(parent)
	handle := &pollerHandle{ctx: pollCtx, cancel: cancel}
	m.pollersMu.Lock()
	m.pollers[pgUUID(br.ID)] = handle
	m.pollersMu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			// Self-cleanup: ensure the map doesn't hold a stale entry
			// after the goroutine exits. Compare by pollCtx pointer —
			// each context.WithCancel returns a unique *cancelCtx, so
			// "existing.ctx == pollCtx" is true iff this is still our
			// entry. If AddBridge replaced us mid-flight, the map now
			// holds a different handle and we leave it alone.
			m.pollersMu.Lock()
			if existing, ok := m.pollers[pgUUID(br.ID)]; ok && existing.ctx == pollCtx {
				delete(m.pollers, pgUUID(br.ID))
			}
			m.pollersMu.Unlock()
			cancel()
		}()
		ctx := pollCtx
		driver := m.drivers[br.Type]
		var lastIdentityCheck time.Time // bot-identity getMe throttle (all bridges)

		// Run-starting events (messages, approve/deny taps) are handled one
		// at a time by this worker — concurrent runs in a single
		// conversation aren't validated yet. Cancel taps bypass the worker
		// (see the poll loop) so a cancel can reach a run that is still in
		// flight. The buffer sits above getUpdates' 100-update max batch so
		// a single poll never blocks the loop — which keeps cancel taps
		// getting fetched promptly even while the worker is busy.
		msgEvents := make(chan BridgeEvent, 128)
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ev := <-msgEvents:
					if err := m.HandleEvent(ctx, ev); err != nil {
						m.logger.Error("handle event failed",
							zap.String("bridge", br.Name), zap.Error(err))
					}
				}
			}
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			events, err := driver.Poll(ctx, &br)
			if err != nil {
				if ctx.Err() != nil {
					return // shutting down
				}
				m.logger.Error("poll failed",
					zap.String("bridge", br.Name),
					zap.Error(err))
				q := dbq.New(m.db.Pool())
				_ = q.UpdateBridgeStatus(ctx, dbq.UpdateBridgeStatusParams{
					ID:     br.ID,
					Status: "error",
				})
				// Back off before retrying. Jitter spreads out the retries
				// when several bridges fail in the same instant (a local
				// network blip drops every poller's TCP socket within ~1 ms
				// of each other); without jitter all of them would hammer
				// the upstream simultaneously on the next attempt.
				backoff := 30*time.Second + time.Duration(rand.Int64N(int64(10*time.Second)))
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				continue
			}

			// A cancel tap must reach its run while the run is still in
			// flight — it can't wait behind the serial worker, since the
			// worker is busy running the very thing being cancelled. It
			// starts no run (just fires CancelRun), so handling it
			// concurrently introduces no parallel run. Every other event
			// goes through the worker, one at a time.
			for _, event := range events {
				if isCancelTap(event) {
					m.wg.Add(1)
					go func(ev BridgeEvent) {
						defer m.wg.Done()
						if err := m.HandleEvent(ctx, ev); err != nil {
							m.logger.Error("handle event failed",
								zap.String("bridge", br.Name), zap.Error(err))
						}
					}(event)
					continue
				}
				select {
				case msgEvents <- event:
				case <-ctx.Done():
					return
				}
			}

			// Update last_polled_at and persisted config (e.g. poll offset).
			q := dbq.New(m.db.Pool())
			_ = q.UpdateBridgeLastPolled(ctx, dbq.UpdateBridgeLastPolledParams{
				ID:     br.ID,
				Config: br.Config,
			})

			// Periodically re-sync the bot-controlled identity (display name +
			// @handle, plus can_manage_bots for manager bridges) and repair the
			// Telegram Web App menu button. Throttled to ~10 min; the zero
			// lastIdentityCheck makes the first iteration run it.
			if m.reconcileBridgeIdentity(ctx, &br, &lastIdentityCheck) {
				m.syncWebAppMenuButton(ctx, driver, br)
			}
		}
	}()
}
