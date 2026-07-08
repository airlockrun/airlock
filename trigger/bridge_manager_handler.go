package trigger

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// bridgeIdentityInterval is how often a bridge re-syncs its bot-controlled
// identity (display name + @handle, plus can_manage_bots for manager bridges)
// via getMe, interleaved between poll cycles.
const bridgeIdentityInterval = 10 * time.Minute

// handleManagerBotCreated turns a Telegram managed_bot_created service message
// (seen on a manager bridge) into a bridge for the freshly-created bot. The
// actual ingest (idempotency, session correlation, token fetch, bridge
// create) lives in the bridges service via the wired callback — keeping all
// bridge-creation logic in one place. br.BotTokenRef is the decrypted manager
// token (HandleEvent decrypts before dispatch).
func (m *BridgeManager) handleManagerBotCreated(ctx context.Context, br dbq.Bridge, evt ManagedBotEvent) error {
	if evt.BotID == 0 || evt.Username == "" {
		return nil
	}
	if m.managedBotIngest == nil {
		m.logger.Warn("managed_bot_created received but ingest not wired",
			zap.String("bridge", br.Name))
		return nil
	}
	sysConvID, err := m.managedBotIngest(ctx, br.BotTokenRef, evt.BotID, evt.Username)
	if err != nil {
		return err
	}

	// If the bot was requested from a sysagent conversation (create_tg_bot),
	// resume that conversation so the agent announces the ready bot in-character
	// and hands over the open link — same mechanism as a build/upgrade
	// completion. Its reply streams back through the system bridge.
	if sysConvID != "" && m.sysagent != nil {
		if cid, perr := uuid.Parse(sysConvID); perr == nil {
			if nerr := m.sysagent.NotifyBotCreated(ctx, cid, evt.Username); nerr != nil {
				m.logger.Warn("notify bot created (sysagent resume) failed",
					zap.String("bridge", br.Name),
					zap.String("new_bot", evt.Username),
					zap.Error(nerr))
			}
			return nil
		}
	}

	// Web-UI / non-sysagent path: no conversation to resume, so post the open
	// link straight to the chat the creation happened in (evt.ExternalID — the
	// exact chat/account, so a user with multiple linked Telegram accounts gets
	// it in the right one). Opening the bot fires its first /start, which binds
	// the web-app menu button.
	if evt.ExternalID != "" {
		link := "https://t.me/" + evt.Username
		msg := "✅ Your bot @" + evt.Username + " is ready. Open it to finish setup:\n" + link
		if serr := m.SendMessage(ctx, uuid.UUID(br.ID.Bytes), evt.ExternalID, msg); serr != nil {
			m.logger.Warn("post-create deep link send failed",
				zap.String("bridge", br.Name),
				zap.String("new_bot", evt.Username),
				zap.Error(serr))
		}
	}
	return nil
}

// reconcileBridgeIdentity re-syncs a bridge's bot-controlled identity from a
// getMe call, throttled to bridgeIdentityInterval. For every bridge it refreshes
// the display name (the bridge name) + bot_username (both bot-owned; the operator
// never sets them). For manager bridges it additionally reconciles manager_error
// (set when can_manage_bots is missing or getMe fails, cleared when healthy) —
// the admin's is_manager intent is never auto-flipped; manager behavior gates on
// the live capability instead. last is the per-poller throttle timestamp
// (zero → run on the first poll). Values are kept as-is on a getMe blip rather
// than blanked. Returns true when the throttle allowed a reconciliation pass.
func (m *BridgeManager) reconcileBridgeIdentity(ctx context.Context, br *dbq.Bridge, last *time.Time) bool {
	now := time.Now()
	if !last.IsZero() && now.Sub(*last) < bridgeIdentityInterval {
		return false
	}
	*last = now

	tg, ok := m.drivers[br.Type].(*TelegramDriver)
	if !ok {
		return true // Telegram is the only platform; defensive
	}
	username, name, _, canManage, err := tg.GetMeFull(ctx, br.BotTokenRef)
	q := dbq.New(m.db.Pool())

	if err == nil {
		// Don't blank a field if Telegram omitted it.
		newName, newUsername := br.Name, br.BotUsername
		if name != "" {
			newName = name
		}
		if username != "" {
			newUsername = username
		}
		if newName != br.Name || newUsername != br.BotUsername {
			if rerr := q.UpdateBridgeIdentity(ctx, dbq.UpdateBridgeIdentityParams{
				ID:          br.ID,
				Name:        newName,
				BotUsername: newUsername,
			}); rerr != nil {
				m.logger.Warn("refresh bridge identity failed",
					zap.String("bridge", br.Name), zap.Error(rerr))
			} else {
				br.Name, br.BotUsername = newName, newUsername
			}
		}
	}

	if !br.IsManager {
		return true
	}
	mgrErr := ""
	switch {
	case err != nil:
		mgrErr = "getMe failed: " + err.Error()
	case !canManage:
		mgrErr = "bot @" + br.BotUsername + " does not have can_manage_bots enabled in BotFather"
	}
	if rerr := q.ReconcileManagerBridge(ctx, dbq.ReconcileManagerBridgeParams{
		ID:           br.ID,
		BotUsername:  br.BotUsername,
		ManagerError: mgrErr,
	}); rerr != nil {
		m.logger.Warn("reconcile manager bridge failed",
			zap.String("bridge", br.Name), zap.Error(rerr))
		return true
	}
	if mgrErr != "" {
		m.logger.Warn("manager bridge capability degraded",
			zap.String("bridge", br.Name), zap.String("error", mgrErr))
	}
	return true
}
