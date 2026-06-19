package trigger

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"go.uber.org/zap"
)

// managerCapabilityInterval is how often a manager bridge re-checks its live
// can_manage_bots capability + bot identity via getMe, interleaved between
// poll cycles.
const managerCapabilityInterval = 10 * time.Minute

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
	return m.managedBotIngest(ctx, br.BotTokenRef, evt.BotID, evt.Username)
}

// reconcileManagerCapability refreshes a manager bridge's bot_username and
// manager_error from a getMe call, throttled to managerCapabilityInterval.
// manager_error is set when can_manage_bots is missing (or getMe fails) and
// cleared when healthy — the admin's is_manager intent is never auto-flipped;
// manager behavior (the deep-link flow) gates on the live capability instead.
// last is the per-poller throttle timestamp (zero → run on first poll).
func (m *BridgeManager) reconcileManagerCapability(ctx context.Context, br *dbq.Bridge, last *time.Time) {
	now := time.Now()
	if !last.IsZero() && now.Sub(*last) < managerCapabilityInterval {
		return
	}
	*last = now

	tg, ok := m.drivers[br.Type].(*TelegramDriver)
	if !ok {
		return // is_manager is Telegram-only; defensive
	}
	username, _, canManage, err := tg.GetMeFull(ctx, br.BotTokenRef)

	mgrErr := ""
	switch {
	case err != nil:
		mgrErr = "getMe failed: " + err.Error()
	case !canManage:
		mgrErr = "bot @" + username + " does not have can_manage_bots enabled in BotFather"
	}
	// Keep the existing username if getMe failed (don't blank it on a blip).
	botUsername := br.BotUsername
	if username != "" {
		botUsername = username
	}

	q := dbq.New(m.db.Pool())
	if rerr := q.ReconcileManagerBridge(ctx, dbq.ReconcileManagerBridgeParams{
		ID:           br.ID,
		BotUsername:  botUsername,
		ManagerError: mgrErr,
	}); rerr != nil {
		m.logger.Warn("reconcile manager bridge failed",
			zap.String("bridge", br.Name), zap.Error(rerr))
		return
	}
	br.BotUsername = botUsername
	if mgrErr != "" {
		m.logger.Warn("manager bridge capability degraded",
			zap.String("bridge", br.Name), zap.String("error", mgrErr))
	}
}
