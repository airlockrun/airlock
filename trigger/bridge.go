package trigger

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ResponseEvent represents an NDJSON event from the agent response stream,
// forwarded to the bridge driver for progressive delivery.
type ResponseEvent struct {
	Type       string // "text-delta", "tool-call", "tool-result", "confirmation_required", "info"
	Text       string // for text-delta / info: the delta text or info message
	ToolCallID string // for tool_call/tool_result
	ToolName   string // for tool_call/tool_result
	ToolInput  string // for tool_call: the tool arguments
	ToolOutput string // for tool_result: the tool output
	ToolError  string // for tool_result: error message if failed
	Raw        []byte // full NDJSON line (for non-text events drivers may need)

	// Populated when Type == "confirmation_required":
	RunID      string
	Permission string
	Patterns   []string
	Code       string
}

// BridgeCallback represents an interactive UI acknowledgement — a button tap
// on an inline keyboard or similar platform-native affordance. Drivers that
// don't support rich UI leave this nil.
type BridgeCallback struct {
	Data  string // opaque payload, e.g. "approve:<runID>"
	AckID string // platform-specific ack handle (Telegram callback_query.id)
}

// BridgeEvent represents a normalized incoming event from any platform.
// Either Text/Files (new user message) or Callback (button tap) is populated.
type BridgeEvent struct {
	BridgeID   uuid.UUID
	ExternalID string // platform chat_id (Telegram chat ID, etc.)
	SenderID   string // platform user ID of sender (for identity lookup)
	SenderName string
	Text       string
	Files      []BridgeFile // attached files (photos, documents)
	Callback   *BridgeCallback
	RawPayload []byte
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
}

// CommandRegistrar is an optional BridgeDriver capability: platforms with
// a native command menu (Telegram setMyCommands, Discord app commands, ...)
// implement it to receive the slash-command registry on activation.
// Drivers without such a menu simply don't implement it.
type CommandRegistrar interface {
	RegisterCommands(ctx context.Context, br dbq.Bridge, cmds []SlashCommand) error
}

// BridgeManager manages bridge drivers and routes events to agents.
type BridgeManager struct {
	drivers    map[string]BridgeDriver
	prompter   *PromptProxy
	db         *db.DB
	encryptor  *crypto.Encryptor
	logger     *zap.Logger
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	hmacSecret string // for generating identity-linking URLs
	publicURL  string // base URL for identity-linking URLs

	// pollers tracks the cancel func for each running poller, keyed by
	// bridge ID. Needed so RemoveBridge can stop exactly one poller on
	// bridge deletion — without it, a deleted bridge's goroutine would
	// keep calling getUpdates on the same bot token. If the user then
	// recreates the bridge with the same token, two pollers race for
	// the token and Telegram returns 409 Conflict on both.
	pollersMu sync.Mutex
	pollers   map[uuid.UUID]context.CancelFunc

	// linkSent tracks sender IDs that have already received a linking message
	// to avoid spamming them on every message. Reset on restart.
	linkSentMu sync.Mutex
	linkSent   map[string]time.Time
}

// NewBridgeManager creates a BridgeManager.
func NewBridgeManager(drivers map[string]BridgeDriver, prompter *PromptProxy, database *db.DB, encryptor *crypto.Encryptor, hmacSecret, publicURL string, logger *zap.Logger) *BridgeManager {
	return &BridgeManager{
		drivers:    drivers,
		prompter:   prompter,
		db:         database,
		encryptor:  encryptor,
		hmacSecret: hmacSecret,
		publicURL:  publicURL,
		logger:     logger,
		pollers:    make(map[uuid.UUID]context.CancelFunc),
		linkSent:   make(map[string]time.Time),
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
		if br.TokenEncrypted != "" {
			token, err := m.encryptor.Decrypt(br.TokenEncrypted)
			if err != nil {
				m.logger.Error("decrypt bridge token failed",
					zap.String("name", br.Name),
					zap.Error(err))
				continue
			}
			decrypted.TokenEncrypted = token
		}

		if err := driver.Activate(ctx, decrypted); err != nil {
			m.logger.Error("bridge activate failed",
				zap.String("name", br.Name),
				zap.Error(err))
			continue
		}
		m.registerCommands(ctx, driver, decrypted)
		m.startPoller(ctx, decrypted)
	}

	m.logger.Info("bridge manager started", zap.Int("pollers", len(bridges)))
	return nil
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
	token, err := m.encryptor.Decrypt(br.TokenEncrypted)
	if err != nil {
		m.logger.Error("add bridge: decrypt token", zap.Error(err))
		return
	}
	br.TokenEncrypted = token
	if err := driver.Activate(m.ctx, br); err != nil {
		m.logger.Error("add bridge: activate", zap.Error(err))
		return
	}
	m.registerCommands(m.ctx, driver, br)
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

// cancelPoller stops the poller goroutine for a specific bridge ID, if any.
// Holds pollersMu while swapping/deleting so concurrent AddBridge+RemoveBridge
// calls can't race on the map.
func (m *BridgeManager) cancelPoller(bridgeID uuid.UUID) {
	m.pollersMu.Lock()
	cancel, ok := m.pollers[bridgeID]
	delete(m.pollers, bridgeID)
	m.pollersMu.Unlock()
	if ok {
		cancel()
	}
}

// Stop gracefully shuts down all pollers.
func (m *BridgeManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

// HandleEvent processes a parsed BridgeEvent — routes to agent via PromptProxy.
func (m *BridgeManager) HandleEvent(ctx context.Context, event BridgeEvent) error {
	q := dbq.New(m.db.Pool())
	br, err := q.GetBridgeByID(ctx, toPgUUID(event.BridgeID))
	if err != nil {
		return fmt.Errorf("get bridge: %w", err)
	}

	if !br.AgentID.Valid {
		return nil // system bridge with no agent bound — drop event for now
	}
	agentID := pgUUID(br.AgentID)

	// Decrypt token for driver.
	if br.TokenEncrypted != "" {
		token, err := m.encryptor.Decrypt(br.TokenEncrypted)
		if err != nil {
			return fmt.Errorf("decrypt bridge token: %w", err)
		}
		br.TokenEncrypted = token
	}

	driver := m.drivers[br.Type]

	// Resolve user_id from platform identity (DM-only mode). Resolved before
	// SendStream so we can look up per-conversation settings (echo) and pass
	// them into the driver before the first event is processed.
	identity, err := q.GetPlatformIdentity(ctx, dbq.GetPlatformIdentityParams{
		Platform:       br.Type,
		PlatformUserID: event.SenderID,
	})
	if err != nil {
		// Send a linking message — but only once per sender per 10 minutes.
		senderKey := br.Type + ":" + event.SenderID
		m.linkSentMu.Lock()
		lastSent, alreadySent := m.linkSent[senderKey]
		if !alreadySent || time.Since(lastSent) > 10*time.Minute {
			m.linkSent[senderKey] = time.Now()
			m.linkSentMu.Unlock()

			if tg, ok := driver.(*TelegramDriver); ok && m.publicURL != "" {
				chatID, _ := strconv.ParseInt(event.ExternalID, 10, 64)
				if chatID != 0 {
					linkURL := buildAuthExternalURL(m.publicURL, m.hmacSecret, br.Type, pgUUID(br.ID).String(), event.SenderID)
					msg := fmt.Sprintf("To use this bot, please link your Airlock account:\n%s", linkURL)
					_ = tg.SendMessage(ctx, br.TokenEncrypted, chatID, msg)
				}
			}
		} else {
			m.linkSentMu.Unlock()
		}
		return nil
	}
	userID := pgUUID(identity.UserID)

	// Resolve effective echo for this conversation. GetConversationBySource
	// may return no row on the first message — in that case we fall back to
	// the driver default (Telegram → off).
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
		_, cbErr := m.prompter.HandleCallback(ctx, agentID, event.BridgeID, userID, event.ExternalID, event.Callback.Data, respEvents)
		// Wait for driver to finish rendering anything queued before we ack.
		wg.Wait()
		// Ack the tap so Telegram clears its loading spinner. Failure is
		// non-fatal — the spinner just expires after ~15s.
		if tg, ok := driver.(*TelegramDriver); ok && event.Callback.AckID != "" {
			_ = tg.AnswerCallbackQuery(ctx, br.TokenEncrypted, event.Callback.AckID, "")
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
	_, err = m.prompter.HandleMessage(ctx, agentID, event.BridgeID, userID, event.ExternalID, true, event.Text, event.Files, respEvents)
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

	token, err := m.encryptor.Decrypt(br.TokenEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt token: %w", err)
	}

	driver, ok := m.drivers[br.Type]
	if !ok {
		return fmt.Errorf("no driver for type %q", br.Type)
	}

	if tg, ok := driver.(*TelegramDriver); ok {
		chatID, err := strconv.ParseInt(externalID, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid chat ID: %w", err)
		}
		return tg.SendParts(ctx, token, chatID, parts)
	}

	return fmt.Errorf("driver %q does not support SendParts", br.Type)
}

// SendMessage sends a text message to a bridge conversation. Convenience wrapper.
func (m *BridgeManager) SendMessage(ctx context.Context, bridgeID uuid.UUID, externalID, text string) error {
	return m.SendParts(ctx, bridgeID, externalID, []agentsdk.DisplayPart{{Type: "text", Text: text}})
}

// startPoller starts a background goroutine that polls a bridge for new events.
// The goroutine's context is scoped to this bridge ID so RemoveBridge /
// AddBridge-on-same-id can stop exactly one poller without tearing down
// others.
func (m *BridgeManager) startPoller(parent context.Context, br dbq.Bridge) {
	pollCtx, cancel := context.WithCancel(parent)
	m.pollersMu.Lock()
	m.pollers[pgUUID(br.ID)] = cancel
	m.pollersMu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			// Self-cleanup: ensure the map doesn't hold a stale entry
			// after the goroutine exits. Only remove our own entry —
			// if AddBridge replaced us with a new poller mid-flight,
			// leave its cancel in place. reflect.ValueOf(fn).Pointer
			// is the idiomatic way to compare func values in Go.
			ourPtr := reflect.ValueOf(cancel).Pointer()
			m.pollersMu.Lock()
			if existing, ok := m.pollers[pgUUID(br.ID)]; ok &&
				reflect.ValueOf(existing).Pointer() == ourPtr {
				delete(m.pollers, pgUUID(br.ID))
			}
			m.pollersMu.Unlock()
			cancel()
		}()
		ctx := pollCtx
		driver := m.drivers[br.Type]

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
				// Back off before retrying.
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}
				continue
			}

			for _, event := range events {
				if err := m.HandleEvent(ctx, event); err != nil {
					m.logger.Error("handle event failed",
						zap.String("bridge", br.Name),
						zap.Error(err))
				}
			}

			// Update last_polled_at and persisted config (e.g. poll offset).
			q := dbq.New(m.db.Pool())
			_ = q.UpdateBridgeLastPolled(ctx, dbq.UpdateBridgeLastPolledParams{
				ID:     br.ID,
				Config: br.Config,
			})
		}
	}()
}
