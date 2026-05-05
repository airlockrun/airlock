package trigger

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"go.uber.org/zap"
)

// publicSweeperFinalMessage is what the bot says before a public
// conversation is dropped. Kept short so it renders as a single chat
// bubble across platforms.
const publicSweeperFinalMessage = "Conversation completed."

// SweepExpiredPublicConversations runs one pass: list public bridge
// conversations whose updated_at is older than the bridge's configured
// TTL, send a final "Conversation completed" message, then delete the
// conversation row (which cascade-drops messages via the FK).
//
// Sends are best-effort — a failure to deliver the final message
// (network blip, revoked bot token, deleted DM channel) does not block
// deletion. Local state is the source of truth; the user just doesn't
// see the goodbye.
func SweepExpiredPublicConversations(ctx context.Context, database *db.DB, mgr *BridgeManager, logger *zap.Logger) {
	q := dbq.New(database.Pool())
	rows, err := q.ListExpiredPublicConversations(ctx)
	if err != nil {
		logger.Error("list expired public conversations", zap.Error(err))
		return
	}
	if len(rows) == 0 {
		return
	}

	for _, r := range rows {
		bridgeID := pgUUID(r.BridgeID)
		external := r.ExternalID.String

		if external != "" && mgr != nil {
			if err := mgr.SendMessage(ctx, bridgeID, external, publicSweeperFinalMessage); err != nil {
				logger.Warn("public sweeper: deliver final message failed",
					zap.String("bridge_id", bridgeID.String()),
					zap.String("external_id", external),
					zap.Error(err),
				)
			}
		}

		if err := q.DeleteConversation(ctx, r.ID); err != nil {
			logger.Error("public sweeper: delete conversation",
				zap.String("conversation_id", pgUUID(r.ID).String()),
				zap.Error(err),
			)
			continue
		}
	}
	logger.Info("public sweeper: pass complete", zap.Int("expired", len(rows)))
}

// StartPublicSweeper kicks off a goroutine that runs
// SweepExpiredPublicConversations every interval until ctx is done.
// Single-replica only — for multi-replica deployments this needs a
// Postgres advisory lock so exactly one airlock holds the sweeper at
// any moment.
func StartPublicSweeper(ctx context.Context, database *db.DB, mgr *BridgeManager, interval time.Duration, logger *zap.Logger) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				SweepExpiredPublicConversations(ctx, database, mgr, logger)
			}
		}
	}()
}
