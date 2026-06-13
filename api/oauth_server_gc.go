package api

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"go.uber.org/zap"
)

// InboundOAuthGC sweeps expired authorization codes, expired/
// long-consumed refresh tokens, and ancient grants. Mirrors
// oauth.RefreshJob in cadence — 5min ticker, started from
// cmd/airlock/serve.go and stopped via ctx cancellation.
//
// The query files document the retention rules:
//   - authz codes: hard delete past expires_at (60s TTL).
//   - refresh tokens: past expires_at OR consumed >7d ago.
//   - grants: revoked-or-expired more than 1y ago.
//
// Each tick is idempotent and safe to call from multiple replicas
// (the DELETE is row-level; concurrent deletes harmlessly target
// disjoint rows because the GC window slides).
type InboundOAuthGC struct {
	db     *db.DB
	logger *zap.Logger
}

func NewInboundOAuthGC(database *db.DB, logger *zap.Logger) *InboundOAuthGC {
	if database == nil {
		panic("api: NewInboundOAuthGC: db is required")
	}
	if logger == nil {
		panic("api: NewInboundOAuthGC: logger is required")
	}
	return &InboundOAuthGC{db: database, logger: logger}
}

// Run blocks until ctx is cancelled, sweeping every 5 minutes.
func (j *InboundOAuthGC) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Run once on startup so the next deploy isn't burdened by stale
	// rows from before the GC was installed.
	j.sweep(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j.sweep(ctx)
		}
	}
}

func (j *InboundOAuthGC) sweep(ctx context.Context) {
	q := dbq.New(j.db.Pool())
	// airlockvet:allow-dbq reason: startup garbage-collection sweep — no caller Principal, runs as airlock-internal housekeeping
	if n, err := q.CleanupExpiredAuthzCodes(ctx); err != nil {
		j.logger.Warn("gc: authz codes", zap.Error(err))
	} else if n > 0 {
		j.logger.Debug("gc: authz codes", zap.Int64("deleted", n))
	}
	// airlockvet:allow-dbq reason: startup garbage-collection sweep — no caller Principal, runs as airlock-internal housekeeping
	if n, err := q.CleanupExpiredRefreshTokens(ctx); err != nil {
		j.logger.Warn("gc: refresh tokens", zap.Error(err))
	} else if n > 0 {
		j.logger.Debug("gc: refresh tokens", zap.Int64("deleted", n))
	}
	// airlockvet:allow-dbq reason: startup garbage-collection sweep — no caller Principal, runs as airlock-internal housekeeping
	if n, err := q.CleanupExpiredGrants(ctx); err != nil {
		j.logger.Warn("gc: grants", zap.Error(err))
	} else if n > 0 {
		j.logger.Debug("gc: grants", zap.Int64("deleted", n))
	}
}
