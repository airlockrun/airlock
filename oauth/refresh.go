package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// RefreshJob refreshes OAuth tokens before they expire.
type RefreshJob struct {
	db        *db.DB
	encryptor secrets.Store
	client    *Client
	interval  time.Duration
	buffer    time.Duration
	logger    *zap.Logger
}

// NewRefreshJob creates a RefreshJob with default interval (5 min) and buffer (10 min).
func NewRefreshJob(database *db.DB, encryptor secrets.Store, client *Client, logger *zap.Logger) *RefreshJob {
	return &RefreshJob{
		db:        database,
		encryptor: encryptor,
		client:    client,
		interval:  5 * time.Minute,
		buffer:    10 * time.Minute,
		logger:    logger,
	}
}

// Run starts the background refresh loop. Blocks until ctx is cancelled.
// Runs an immediate refresh on startup so tokens that expired while the
// process was down are caught without waiting for the first tick.
func (j *RefreshJob) Run(ctx context.Context) {
	j.refreshOnce(ctx)

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j.refreshOnce(ctx)
		}
	}
}

func (j *RefreshJob) refreshOnce(ctx context.Context) {
	q := dbq.New(j.db.Pool())

	threshold := pgtype.Timestamptz{
		Time:  time.Now().Add(j.buffer),
		Valid: true,
	}
	// Pre-warm: refresh anything expiring within the buffer so the on-demand
	// path (EnsureConnectionToken at request time) rarely pays for a refresh.
	refreshIfBefore := time.Now().Add(j.buffer)

	conns, err := q.ListExpiringConnections(ctx, threshold)
	if err != nil {
		j.logger.Error("list expiring connections failed", zap.Error(err))
	}
	for _, conn := range conns {
		if conn.RefreshToken == "" {
			continue
		}
		_, err := EnsureConnectionToken(ctx, j.db, j.encryptor, j.client, j.logger, conn.ID, refreshIfBefore)
		if err != nil && !errors.Is(err, ErrNeedsReauth) {
			j.logger.Warn("token refresh failed",
				zap.String("kind", "connection"), zap.String("agent", conn.AgentSlug),
				zap.String("slug", conn.Slug), zap.Error(err))
		}
	}

	mcpServers, err := q.ListExpiringMCPServers(ctx, threshold)
	if err != nil {
		j.logger.Error("list expiring MCP servers failed", zap.Error(err))
	}
	for _, srv := range mcpServers {
		if srv.RefreshToken == "" {
			continue
		}
		_, err := EnsureMCPServerToken(ctx, j.db, j.encryptor, j.client, j.logger, srv.ID, refreshIfBefore)
		if err != nil && !errors.Is(err, ErrNeedsReauth) {
			j.logger.Warn("token refresh failed",
				zap.String("kind", "mcp"), zap.String("agent", srv.AgentSlug),
				zap.String("slug", srv.Slug), zap.Error(err))
		}
	}

	// Cleanup expired OAuth states.
	if err := q.CleanupExpiredOAuthStates(ctx); err != nil {
		j.logger.Error("cleanup expired oauth states failed", zap.Error(err))
	}
}
