// Package usage serves read-only rollups over the llm_usage spend ledger for
// the admin Usage view: a window summary plus per-agent and per-model
// breakdowns. The ledger is durable (rows survive agent/user deletion), so a
// deleted agent still appears under its snapshot identity.
package usage

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Report is the full Usage view payload for one window.
type Report struct {
	WindowDays int32
	Summary    dbq.UsageSummaryRow
	ByAgent    []dbq.UsageByAgentRow
	ByModel    []dbq.UsageByModelRow
}

type Service struct {
	db     *db.DB
	logger *zap.Logger
}

func New(d *db.DB, logger *zap.Logger) *Service {
	if d == nil || logger == nil {
		panic("usage: nil dependency")
	}
	return &Service{db: d, logger: logger}
}

// Get returns the ledger rollups for the last windowDays (0 = all time).
// Admin-gated via the tenant axis.
func (s *Service) Get(ctx context.Context, p authz.Principal, windowDays int32) (Report, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantUsageView, uuid.Nil); err != nil {
		return Report{}, err
	}
	// windowDays <= 0 means all-time: a zero timestamptz is the lowest bound,
	// so created_at >= it matches every row.
	var since pgtype.Timestamptz
	if windowDays > 0 {
		since = pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -int(windowDays)), Valid: true}
	} else {
		since = pgtype.Timestamptz{Time: time.Time{}, Valid: true}
	}

	summary, err := q.UsageSummary(ctx, since)
	if err != nil {
		s.logger.Error("usage summary failed", zap.Error(err))
		return Report{}, err
	}
	byAgent, err := q.UsageByAgent(ctx, since)
	if err != nil {
		s.logger.Error("usage by agent failed", zap.Error(err))
		return Report{}, err
	}
	byModel, err := q.UsageByModel(ctx, since)
	if err != nil {
		s.logger.Error("usage by model failed", zap.Error(err))
		return Report{}, err
	}
	if windowDays < 0 {
		windowDays = 0
	}
	return Report{WindowDays: windowDays, Summary: summary, ByAgent: byAgent, ByModel: byModel}, nil
}
