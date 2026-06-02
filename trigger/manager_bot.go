// trigger/manager_bot.go houses the singleton Telegram Managed Bots
// poller — the bot whose can_manage_bots flag is true and that the
// platform's operators use to create new bots on behalf of their
// users. The poller shares the same getUpdates long-poll shape as
// the per-bridge bridge pollers in bridge.go, so cohabitation in
// trigger/ keeps the goroutine lifecycle conventions consistent —
// only the update-type handlers differ.
//
// Flow (Bot API 9.6):
//  1. Airlock UI POST /bridges/managed/sessions inserts a session
//     row + returns deep_link
//     https://t.me/newbot/<manager_username>/<suggested_username>?name=<...>.
//  2. User opens the link in Telegram. Telegram's native bot-creation
//     UI walks them through.
//  3. On completion Telegram delivers a ManagedBotCreated{bot} service
//     message into the manager-bot's chat with the creator. We match
//     bot.username against the session nonce (the suggested_username
//     we set on the deeplink — Telegram preserves it through the
//     flow), fetch the token via getManagedBotToken{user_id: bot.id},
//     call bridges.Service.CreateFromManagedSession, and delete the
//     session. The complementary ManagedBotUpdated event isn't
//     consumed: rotation/owner-change is rare for managed bots in
//     v1, and the Created path is sufficient for creation.
package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// ManagerBotTokenScope is the encryptor scope under which the
// admin-configured manager bot token is stored. system_settings holds
// the ciphertext; the poller decrypts at Start time. Exported so the
// settings handler can encrypt under the same scope when persisting
// a new token.
const ManagerBotTokenScope = "system/telegram_manager_bot_token"

// ValidateManagerBotToken does a getMe round-trip against Telegram
// and returns (username, can_manage_bots, error). Used by the
// settings handler when an admin pastes a new manager-bot token, so
// validation happens against the same wire shape the poller uses.
func ValidateManagerBotToken(ctx context.Context, token string) (string, bool, error) {
	me, err := telegramGetMe(ctx, token)
	if err != nil {
		return "", false, err
	}
	return me.Username, me.CanManageBots, nil
}

// ManagerBot is the singleton Telegram Managed Bots poller. One per
// airlock instance; configured via system_settings.telegram_manager_bot_*.
// Start spawns the poll goroutine; Stop cancels it; Reload re-reads
// the stored token (called after a settings update).
//
// The poller is *separate* from the per-bridge bridge pollers — those
// hold a bridge row's token, this one holds the admin-level manager
// bot's. Failures route through the system_settings.telegram_manager_bot_error
// column (visible inline on the settings page) rather than panicking
// — invalid token or revoked can_manage_bots shouldn't take down
// airlock.
type ManagerBot struct {
	db        *db.DB
	encryptor secrets.Store
	bridges   *bridgessvc.Service
	bridgeMgr *BridgeManager
	logger    *zap.Logger

	mu       sync.Mutex
	cancel   context.CancelFunc
	running  bool
	username atomic.Value // string; "" until first getMe success
	offset   int64        // long-poll offset (incremented per processed update)
}

// NewManagerBot wires the poller. Start must be called separately so
// the caller controls lifecycle (e.g. defer Stop on shutdown).
func NewManagerBot(database *db.DB, encryptor secrets.Store, bridges *bridgessvc.Service, bridgeMgr *BridgeManager, logger *zap.Logger) *ManagerBot {
	if database == nil {
		panic("manager_bot: db is required")
	}
	if encryptor == nil {
		panic("manager_bot: encryptor is required")
	}
	if bridges == nil {
		panic("manager_bot: bridges service is required")
	}
	if bridgeMgr == nil {
		panic("manager_bot: bridge manager is required")
	}
	if logger == nil {
		panic("manager_bot: logger is required")
	}
	mb := &ManagerBot{
		db:        database,
		encryptor: encryptor,
		bridges:   bridges,
		bridgeMgr: bridgeMgr,
		logger:    logger,
	}
	mb.username.Store("")
	return mb
}

// Username returns the manager bot's @handle resolved by getMe at
// Start time (empty when the poller isn't running or hasn't yet
// validated the token). The managedbots service reads this via a
// callback to template deep links — keeping the value an atomic
// makes a Reload-during-CreateSession race observable as
// "stale-but-correct" rather than torn.
func (mb *ManagerBot) Username() string {
	v, _ := mb.username.Load().(string)
	return v
}

// Start reads the configured token, calls getMe to validate, and
// spawns the poll goroutine if validation succeeds. Validation
// failures (no token, network error, can_manage_bots=false, revoked)
// are recorded in system_settings.telegram_manager_bot_error and
// surfaced inline in the settings UI — the poller silently does
// nothing.
//
// Returns nil on both success ("poller spawned") and the "no token
// configured" case (legitimate empty state). Returns a real error
// only when something the operator can't fix from the UI failed
// (DB write of the error string itself).
func (mb *ManagerBot) Start(ctx context.Context) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	if mb.running {
		return nil
	}

	q := dbq.New(mb.db.Pool())
	cfg, err := q.GetTelegramManagerBotStatus(ctx)
	if err != nil {
		return fmt.Errorf("read manager-bot config: %w", err)
	}
	if cfg.TelegramManagerBotTokenRef == "" {
		// Feature off — clear any stale error from a prior misconfig
		// and stay silent.
		if cfg.TelegramManagerBotError != "" {
			_, _ = q.UpdateTelegramManagerBotToken(ctx, dbq.UpdateTelegramManagerBotTokenParams{
				TokenRef:  "",
				ErrorText: "",
			})
		}
		return nil
	}

	token, err := mb.encryptor.Get(ctx, ManagerBotTokenScope, cfg.TelegramManagerBotTokenRef)
	if err != nil {
		mb.recordError(ctx, q, cfg.TelegramManagerBotTokenRef, "decrypt token: "+err.Error())
		return nil
	}

	me, err := telegramGetMe(ctx, token)
	if err != nil {
		mb.recordError(ctx, q, cfg.TelegramManagerBotTokenRef, "getMe: "+err.Error())
		return nil
	}
	if !me.CanManageBots {
		mb.recordError(ctx, q, cfg.TelegramManagerBotTokenRef,
			"bot @"+me.Username+" does not have can_manage_bots enabled in BotFather")
		return nil
	}

	// Healthy. Clear any prior error and start polling.
	if cfg.TelegramManagerBotError != "" {
		_, _ = q.UpdateTelegramManagerBotToken(ctx, dbq.UpdateTelegramManagerBotTokenParams{
			TokenRef:  cfg.TelegramManagerBotTokenRef,
			ErrorText: "",
		})
	}
	mb.username.Store(me.Username)
	mb.logger.Info("manager bot poller starting", zap.String("username", me.Username))

	pollCtx, cancel := context.WithCancel(ctx)
	mb.cancel = cancel
	mb.running = true
	go mb.run(pollCtx, token)
	return nil
}

// Stop cancels the poll goroutine. Safe to call when not running.
func (mb *ManagerBot) Stop() {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	if !mb.running {
		return
	}
	mb.cancel()
	mb.running = false
	mb.username.Store("")
}

// Reload re-reads the configured token and (re)starts the poller.
// Called by the settings handler after PUT /settings/telegram-manager-bot.
// Idempotent.
func (mb *ManagerBot) Reload(ctx context.Context) error {
	mb.Stop()
	return mb.Start(ctx)
}

func (mb *ManagerBot) recordError(ctx context.Context, q *dbq.Queries, tokenRef, errText string) {
	mb.logger.Warn("manager bot configuration error", zap.String("error", errText))
	if _, err := q.UpdateTelegramManagerBotToken(ctx, dbq.UpdateTelegramManagerBotTokenParams{
		TokenRef:  tokenRef,
		ErrorText: errText,
	}); err != nil {
		mb.logger.Error("persist manager-bot error failed", zap.Error(err))
	}
}

// run is the long-poll loop. Each round: getUpdates with offset →
// dispatch handler per update → bump offset. On any transient
// failure (network, 5xx) we back off and retry; on a fatal failure
// (revoked token, can_manage_bots dropped) we stop and record the
// error.
func (mb *ManagerBot) run(ctx context.Context, token string) {
	defer mb.logger.Info("manager bot poller stopped")
	const pollTimeout = 25 // seconds
	backoff := time.Second

	for {
		if ctx.Err() != nil {
			return
		}
		raws, err := telegramGetUpdates(ctx, token, mb.offset, pollTimeout)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			mb.logger.Warn("manager bot getUpdates failed",
				zap.Int64("offset", mb.offset), zap.Error(err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		for _, raw := range raws {
			var u telegramUpdateRaw
			if perr := json.Unmarshal(raw, &u); perr != nil {
				mb.logger.Warn("manager bot: malformed update",
					zap.String("raw", string(raw)), zap.Error(perr))
				continue
			}
			mb.dispatchUpdate(ctx, token, u)
			if u.UpdateID >= mb.offset {
				mb.offset = u.UpdateID + 1
			}
		}
	}
}

// dispatchUpdate routes a Bot API 9.6 update. We only consume the
// nested ManagedBotCreated service message on creation; everything
// else (ordinary chat messages, ManagedBotUpdated rotation events,
// unknown types) is ignored.
func (mb *ManagerBot) dispatchUpdate(ctx context.Context, token string, u telegramUpdateRaw) {
	if u.Message != nil && u.Message.ManagedBotCreated != nil {
		mb.onManagedBotCreated(ctx, token, *u.Message.ManagedBotCreated)
	}
}

// onManagedBotCreated turns a freshly created managed bot into a
// bridge. Correlation is by bot.username == session.nonce — the
// suggested_username we embedded in the deeplink, which Telegram
// preserves through the create flow. Idempotency is the
// bridges.telegram_bot_user_id key (a duplicate Created for the
// same bot.id no-ops).
func (mb *ManagerBot) onManagedBotCreated(ctx context.Context, mbToken string, evt managedBotCreatedRaw) {
	if evt.Bot.ID == 0 || evt.Bot.Username == "" {
		mb.logger.Warn("ManagedBotCreated missing bot.id or bot.username")
		return
	}
	q := dbq.New(mb.db.Pool())
	if _, gerr := q.GetBridgeByTelegramBotUserID(ctx, pgtype.Int8{Int64: evt.Bot.ID, Valid: true}); gerr == nil {
		return
	}
	session, serr := q.GetManagedBotSessionByNonce(ctx, evt.Bot.Username)
	if serr != nil {
		mb.logger.Warn("ManagedBotCreated: no session matches bot.username",
			zap.String("bot_username", evt.Bot.Username))
		return
	}

	newToken, terr := telegramGetManagedBotToken(ctx, mbToken, evt.Bot.ID)
	if terr != nil {
		mb.logger.Error("getManagedBotToken failed",
			zap.Int64("bot_user_id", evt.Bot.ID), zap.Error(terr))
		return
	}
	result, cerr := mb.bridges.CreateFromManagedSession(ctx, bridgessvc.ManagedSessionCreate{
		Session:           session,
		BotUsername:       evt.Bot.Username,
		TelegramBotUserID: evt.Bot.ID,
		RawToken:          newToken,
	})
	if cerr != nil {
		mb.logger.Error("create bridge from managed bot event failed",
			zap.String("nonce", session.Nonce), zap.Error(cerr))
		return
	}
	if derr := q.DeleteManagedBotSessionByNonce(ctx, session.Nonce); derr != nil {
		mb.logger.Warn("delete consumed managed bot session row failed", zap.Error(derr))
	}
	mb.logger.Info("managed bot bridge created",
		zap.Stringer("bridge", uuid.UUID(result.Bridge.ID.Bytes)),
		zap.String("bot_username", evt.Bot.Username))
}

// telegramGetManagedBotToken fetches the token for a managed bot
// after a ManagedBotCreated / ManagedBotUpdated event. Bot API 9.6's
// getManagedBotToken takes the bot's user_id and returns the token
// string directly under `result` (not nested under {token: ...}).
func telegramGetManagedBotToken(ctx context.Context, managerToken string, botUserID int64) (string, error) {
	body := map[string]any{"user_id": botUserID}
	var result struct {
		OK     bool   `json:"ok"`
		Result string `json:"result"`
	}
	if err := telegramAPI(ctx, managerToken, "getManagedBotToken", body, &result); err != nil {
		return "", err
	}
	if !result.OK || result.Result == "" {
		return "", errors.New("getManagedBotToken returned no token")
	}
	return result.Result, nil
}

// ----- Telegram Bot API plumbing (manager-bot-specific helpers) -----
//
// These are deliberately small wrappers rather than reusing the
// TelegramDriver methods. The driver's getUpdates / sendMessage are
// per-bridge (allowed_updates set for chat messages); the manager
// bot needs ManagedBotCreated/Updated in allowed_updates and uses a
// different reply-markup shape on the keyboard. Reusing the driver
// would muddy its responsibility.

// telegramUpdateRaw is the manager-bot-specific Update shape. We
// only consume the nested ManagedBotCreated service message; the
// top-level `managed_bot` (ManagedBotUpdated) rotation event is
// intentionally not handled in v1.
type telegramUpdateRaw struct {
	UpdateID int64               `json:"update_id"`
	Message  *telegramMessageRaw `json:"message,omitempty"`
}

// telegramMessageRaw is the Message subset the manager-bot poller
// cares about. Ordinary text messages reach us by accident if a user
// DMs the manager bot directly, and we ignore them.
type telegramMessageRaw struct {
	ManagedBotCreated *managedBotCreatedRaw `json:"managed_bot_created,omitempty"`
}

// managedBotCreatedRaw — Bot API 9.6 creation service-message. Only
// the bot is included; the token is fetched separately via
// getManagedBotToken{user_id: bot.id}.
type managedBotCreatedRaw struct {
	Bot telegramUserRaw `json:"bot"`
}

type telegramUserRaw struct {
	ID       int64  `json:"id"`
	Username string `json:"username,omitempty"`
	IsBot    bool   `json:"is_bot,omitempty"`
}

type telegramGetMeResult struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	CanManageBots bool   `json:"can_manage_bots"`
}

// telegramGetMe calls Bot API getMe. Used by Start to validate the
// configured manager-bot token + confirm can_manage_bots.
func telegramGetMe(ctx context.Context, token string) (telegramGetMeResult, error) {
	var result struct {
		OK     bool                `json:"ok"`
		Result telegramGetMeResult `json:"result"`
	}
	if err := telegramAPI(ctx, token, "getMe", nil, &result); err != nil {
		return telegramGetMeResult{}, err
	}
	if !result.OK {
		return telegramGetMeResult{}, errors.New("getMe ok=false")
	}
	return result.Result, nil
}

// telegramGetUpdates calls Bot API getUpdates with allowed_updates
// scoped to the manager-bot subset. Long-poll timeout in seconds.
// Returns each update as its raw JSON so the caller can log the
// verbatim payload before parsing — Bot API 9.6's managed-bot wire
// shape is still being firmed up and the raw bytes are the only
// source of truth.
func telegramGetUpdates(ctx context.Context, token string, offset int64, timeoutSec int) ([]json.RawMessage, error) {
	body := map[string]any{
		"offset":  offset,
		"timeout": timeoutSec,
		// allowed_updates intentionally omitted so we receive every
		// update type. Drops a filter that would silently swallow
		// events whose field name doesn't match our guess (the Bot
		// API 9.6 managed-bot field names are still being verified
		// against the live wire). We dispatch only on the types we
		// recognize and log every payload otherwise.
	}
	var result struct {
		OK     bool              `json:"ok"`
		Result []json.RawMessage `json:"result"`
	}
	if err := telegramAPI(ctx, token, "getUpdates", body, &result); err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, errors.New("getUpdates ok=false")
	}
	return result.Result, nil
}

// telegramAPI is the shared JSON POST → JSON decode helper. The
// per-bridge TelegramDriver has its own; we don't share so the
// manager-bot poller doesn't need a *TelegramDriver instance.
func telegramAPI(ctx context.Context, token, method string, body any, out any) error {
	url := "https://api.telegram.org/bot" + token + "/" + method
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s body: %w", method, err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reqBody)
	if err != nil {
		return fmt.Errorf("build %s request: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s request: %w", method, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s http %d", method, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode %s response: %w", method, err)
		}
	}
	return nil
}
