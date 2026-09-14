package execution

import (
	"context"
	"fmt"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/robfig/cron/v3"
)

// MaterializeDueCrons locks due declarations across replicas and atomically
// records app-owned job origins, jobs, and their next scheduled occurrences.
// The scheduler wakes delivery only after this transaction commits.
func (s *Service) MaterializeDueCrons(ctx context.Context, limit int32) (int, error) {
	if limit <= 0 {
		return 0, service.ErrInvalidInput
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	due, err := q.SelectDueAgentJobCrons(ctx, limit)
	if err != nil {
		return 0, err
	}
	parser := cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	for _, declaration := range due {
		occurrence := declaration.NextFireAt.Time
		schedule, err := parser.Parse(declaration.Schedule)
		if err != nil {
			return 0, fmt.Errorf("parse cron %s: %w", declaration.Slug, err)
		}
		next := schedule.Next(occurrence)
		if !next.After(occurrence) {
			return 0, fmt.Errorf("cron %s has no next occurrence", declaration.Slug)
		}
		if _, err := q.InsertAgentJobFromCron(ctx, dbq.InsertAgentJobFromCronParams{
			JobID:       pgID(uuid.New()),
			ScheduledAt: declaration.NextFireAt,
			CronID:      declaration.ID,
		}); err != nil {
			return 0, fmt.Errorf("insert job for cron %s: %w", declaration.Slug, err)
		}
		advanced, err := q.AdvanceAgentJobCron(ctx, dbq.AdvanceAgentJobCronParams{
			NextFireAt:      pgtype.Timestamptz{Time: next.UTC().Truncate(time.Microsecond), Valid: true},
			OccurrenceAt:    declaration.NextFireAt,
			CronID:          declaration.ID,
			PriorNextFireAt: declaration.NextFireAt,
		})
		if err != nil {
			return 0, fmt.Errorf("advance cron %s: %w", declaration.Slug, err)
		}
		if advanced != 1 {
			return 0, fmt.Errorf("advance cron %s: next occurrence changed while locked", declaration.Slug)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(due), nil
}
