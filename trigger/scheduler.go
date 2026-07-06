package trigger

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

// cronParser supports both standard 5-field and optional-second 6-field
// expressions. It is used only to compute next fire times — the scheduler no
// longer holds an in-process ticker.
var cronParser = cron.NewParser(
	cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
)

const (
	// schedulerPollInterval is how often airlock drains due fires. It bounds
	// reminder/cron precision; the DB poll is the always-on, replica-safe
	// substitute for an in-process ticker.
	schedulerPollInterval = 30 * time.Second
	// schedulerBatchSize caps how many due fires one tick claims.
	schedulerBatchSize = 100
)

// Scheduler drains the agent_scheduled_fires due-table and forwards each fire
// to its agent. The poll lives in airlock (always running) so agents stay
// suspended until something is actually due; FOR UPDATE SKIP LOCKED makes the
// claim safe to run from every replica.
type Scheduler struct {
	dispatcher *Dispatcher
	db         *db.DB
	logger     *zap.Logger
	stop       chan struct{}
}

// NewScheduler creates a Scheduler.
func NewScheduler(dispatcher *Dispatcher, db *db.DB, logger *zap.Logger) *Scheduler {
	return &Scheduler{
		dispatcher: dispatcher,
		db:         db,
		logger:     logger,
		stop:       make(chan struct{}),
	}
}

// Start launches the poll loop. It returns immediately; the loop runs until
// Stop or ctx cancellation. Pending fires persist in the DB across restarts,
// so no startup seeding is needed — crons are seeded per agent on sync.
func (s *Scheduler) Start(ctx context.Context) error {
	go s.loop(ctx)
	s.logger.Info("scheduler started", zap.Duration("poll", schedulerPollInterval))
	return nil
}

// Stop halts the poll loop.
func (s *Scheduler) Stop() {
	close(s.stop)
}

func (s *Scheduler) loop(ctx context.Context) {
	t := time.NewTicker(schedulerPollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-t.C:
			s.poll(ctx)
		}
	}
}

// poll claims the currently-due fires — re-arming recurring crons in the same
// transaction so a fire is never lost or double-claimed across replicas — then
// dispatches each outside the transaction.
func (s *Scheduler) poll(ctx context.Context) {
	now := time.Now()
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		s.logger.Error("scheduler: begin tx", zap.Error(err))
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	qtx := dbq.New(tx)
	due, err := qtx.ClaimDueScheduledFires(ctx, schedulerBatchSize)
	if err != nil {
		s.logger.Error("scheduler: claim due fires", zap.Error(err))
		return
	}
	if len(due) == 0 {
		return
	}

	for _, f := range due {
		if f.Recurrence != "" {
			// Recurring (cron): re-arm to the next occurrence, stay pending.
			next, perr := nextFire(f.Recurrence, now)
			if perr != nil {
				s.logger.Error("scheduler: bad recurrence", zap.String("slug", f.Slug), zap.Error(perr))
				_ = qtx.MarkScheduledFire(ctx, dbq.MarkScheduledFireParams{ID: f.ID, Status: "error"})
				continue
			}
			if err := qtx.RescheduleFire(ctx, dbq.RescheduleFireParams{ID: f.ID, FireAt: pgTimestamp(next)}); err != nil {
				s.logger.Error("scheduler: reschedule", zap.Error(err))
			}
		} else {
			// One-shot schedule: terminal once fired.
			if err := qtx.MarkScheduledFire(ctx, dbq.MarkScheduledFireParams{ID: f.ID, Status: "fired"}); err != nil {
				s.logger.Error("scheduler: mark fired", zap.Error(err))
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		s.logger.Error("scheduler: commit", zap.Error(err))
		return
	}
	committed = true

	for _, f := range due {
		s.fire(ctx, f)
	}
}

func (s *Scheduler) fire(ctx context.Context, f dbq.AgentScheduledFire) {
	agentID := pgUUID(f.AgentID)
	timeout := time.Duration(f.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	rc, _, err := s.dispatcher.ForwardFire(ctx, agentID, pgUUID(f.ID).String(), f.Slug, timeout)
	if err != nil {
		// A stopped / unbuilt agent is an expected state, not a fault.
		if errors.Is(err, ErrAgentStopped) || errors.Is(err, ErrAgentNoImage) {
			s.logger.Info("skipping fire for non-runnable agent",
				zap.String("agent", agentID.String()), zap.String("slug", f.Slug))
			return
		}
		s.logger.Error("scheduler: fire failed",
			zap.String("agent", agentID.String()), zap.String("slug", f.Slug))
		return
	}
	// Fire output is not delivered anywhere — drain and close.
	io.Copy(io.Discard, rc)
	rc.Close()

	if f.Source == "cron" {
		q := dbq.New(s.db.Pool())
		if err := q.UpdateScheduleHandlerLastFired(ctx, dbq.UpdateScheduleHandlerLastFiredParams{AgentID: f.AgentID, Slug: f.Slug}); err != nil {
			s.logger.Error("scheduler: update last_fired", zap.Error(err))
		}
	}
}

// ReconcileAgent re-seeds an agent's cron fire rows and orphans pending one-shot
// fires whose schedule handler was removed. Called after each sync so schedule
// changes (added/removed/retimed crons) take effect.
func (s *Scheduler) ReconcileAgent(ctx context.Context, agentID uuid.UUID) error {
	now := time.Now()
	q := dbq.New(s.db.Pool())
	handlers, err := q.ListScheduleHandlersByAgent(ctx, toPgUUID(agentID))
	if err != nil {
		return err
	}
	slugs := make([]string, len(handlers))
	for i, h := range handlers {
		slugs[i] = h.Slug
	}
	// Orphan pending one-shot fires whose schedule handler is gone.
	if err := q.OrphanMissingScheduleFires(ctx, dbq.OrphanMissingScheduleFiresParams{AgentID: toPgUUID(agentID), Slugs: slugs}); err != nil {
		return err
	}
	// Re-seed cron fires from the live, enabled crons.
	if err := q.DeletePendingCronFires(ctx, toPgUUID(agentID)); err != nil {
		return err
	}
	for _, h := range handlers {
		if h.Kind != "cron" || !h.Enabled {
			continue
		}
		next, perr := nextFire(h.Recurrence, now)
		if perr != nil {
			s.logger.Error("scheduler: bad cron recurrence on reconcile",
				zap.String("slug", h.Slug), zap.String("recurrence", h.Recurrence), zap.Error(perr))
			continue
		}
		if _, err := q.InsertScheduledFire(ctx, dbq.InsertScheduledFireParams{
			AgentID:    toPgUUID(agentID),
			Source:     "cron",
			Slug:       h.Slug,
			FireAt:     pgTimestamp(next),
			Recurrence: h.Recurrence,
			TimeoutMs:  h.TimeoutMs,
		}); err != nil {
			s.logger.Error("scheduler: seed cron fire", zap.String("slug", h.Slug), zap.Error(err))
		}
	}
	return nil
}

func nextFire(expr string, now time.Time) (time.Time, error) {
	sched, err := cronParser.Parse(expr)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(now), nil
}

func pgTimestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}
