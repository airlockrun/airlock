package trigger

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

var cronParser = cron.NewParser(
	cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
)

const (
	schedulerPollInterval = 30 * time.Second
	schedulerLeaseRenewal = time.Minute
	schedulerBatchSize    = 16
	schedulerMaxAttempts  = 5
	maxScheduleErrorBytes = 2048
)

// Scheduler leases immutable occurrences in PostgreSQL and acknowledges each
// attempt only after the agent returns a typed handler result.
type Scheduler struct {
	dispatcher *Dispatcher
	db         *db.DB
	logger     *zap.Logger
	owner      uuid.UUID
	stop       chan struct{}
	stopOnce   sync.Once
}

func NewScheduler(dispatcher *Dispatcher, database *db.DB, logger *zap.Logger) *Scheduler {
	if dispatcher == nil {
		panic("trigger: scheduler dispatcher is required")
	}
	if database == nil {
		panic("trigger: scheduler db is required")
	}
	if logger == nil {
		panic("trigger: scheduler logger is required")
	}
	return &Scheduler{dispatcher: dispatcher, db: database, logger: logger, owner: uuid.New(), stop: make(chan struct{})}
}

func (s *Scheduler) Start(ctx context.Context) error {
	go s.loop(ctx)
	s.logger.Info("scheduler started", zap.Duration("poll", schedulerPollInterval), zap.String("owner", s.owner.String()))
	return nil
}

func (s *Scheduler) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *Scheduler) loop(ctx context.Context) {
	ticker := time.NewTicker(schedulerPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-ticker.C:
			s.poll(ctx)
		}
	}
}

func (s *Scheduler) poll(ctx context.Context) {
	q := dbq.New(s.db.Pool())
	if _, err := q.FailExpiredScheduledFires(ctx); err != nil {
		s.logger.Error("scheduler: fail expired final attempts", zap.Error(err))
		return
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		s.logger.Error("scheduler: begin claim", zap.Error(err))
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	qtx := dbq.New(tx)
	due, err := qtx.ClaimDueScheduledFires(ctx, dbq.ClaimDueScheduledFiresParams{
		LeaseOwner: toPgUUID(s.owner), BatchSize: schedulerBatchSize,
	})
	if err != nil {
		s.logger.Error("scheduler: claim due fires", zap.Error(err))
		return
	}
	for _, occurrence := range due {
		if occurrence.Source != "cron" {
			continue
		}
		next, err := nextFire(occurrence.Recurrence, occurrence.FireAt.Time)
		if err != nil {
			s.logger.Error("scheduler: invalid cron recurrence", zap.String("slug", occurrence.Slug), zap.Error(err))
			continue
		}
		if _, err := qtx.InsertScheduledFire(ctx, dbq.InsertScheduledFireParams{
			ID: toPgUUID(uuid.New()), AgentID: occurrence.AgentID, Source: "cron", Slug: occurrence.Slug,
			FireAt: pgTimestamp(next), Recurrence: occurrence.Recurrence, TimeoutMs: occurrence.TimeoutMs, MaxAttempts: schedulerMaxAttempts,
		}); err != nil {
			s.logger.Error("scheduler: insert cron successor", zap.String("slug", occurrence.Slug), zap.Error(err))
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		s.logger.Error("scheduler: commit claims", zap.Error(err))
		return
	}
	committed = true

	var wg sync.WaitGroup
	for _, occurrence := range due {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.fire(ctx, occurrence)
		}()
	}
	wg.Wait()
}

func (s *Scheduler) fire(ctx context.Context, occurrence dbq.AgentScheduledFire) {
	agentID := pgUUID(occurrence.AgentID)
	timeout := time.Duration(occurrence.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	deliveryCtx, cancel := context.WithCancel(ctx)
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		s.renewLease(deliveryCtx, occurrence, cancel)
	}()
	result, _, err := s.dispatcher.ForwardFire(deliveryCtx, agentID, wire.ScheduleFireRequest{
		ID: pgUUID(occurrence.ID).String(), Slug: occurrence.Slug,
		ScheduledAt: occurrence.FireAt.Time, Attempt: int(occurrence.Attempt),
	}, timeout)
	cancel()
	<-renewed
	if err != nil {
		if errors.Is(err, ErrAgentStopped) || errors.Is(err, ErrAgentNoImage) {
			s.recordFailure(ctx, occurrence, err)
			return
		}
		s.logger.Error("scheduler: delivery failed", zap.String("agent", agentID.String()), zap.String("slug", occurrence.Slug), zap.Error(err))
		s.recordFailure(ctx, occurrence, err)
		return
	}
	if result.Status != "success" {
		s.recordFailure(ctx, occurrence, fmt.Errorf("handler %s: %s", result.Status, result.Error))
		return
	}
	q := dbq.New(s.db.Pool())
	updated, err := q.CompleteScheduledFire(ctx, dbq.CompleteScheduledFireParams{
		ID: occurrence.ID, AgentID: occurrence.AgentID, LeaseToken: occurrence.LeaseToken,
	})
	if err != nil {
		s.logger.Error("scheduler: acknowledge success", zap.Error(err))
		return
	}
	if updated == 0 {
		s.logger.Warn("scheduler: stale success acknowledgement", zap.String("occurrence", pgUUID(occurrence.ID).String()))
		return
	}
	if occurrence.Source == "cron" {
		if err := q.UpdateScheduleHandlerLastFired(ctx, dbq.UpdateScheduleHandlerLastFiredParams{AgentID: occurrence.AgentID, Slug: occurrence.Slug}); err != nil {
			s.logger.Error("scheduler: update last fired", zap.Error(err))
		}
	}
}

func (s *Scheduler) renewLease(ctx context.Context, occurrence dbq.AgentScheduledFire, cancel context.CancelFunc) {
	ticker := time.NewTicker(schedulerLeaseRenewal)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updated, err := dbq.New(s.db.Pool()).RenewScheduledFireLease(ctx, dbq.RenewScheduledFireLeaseParams{
				ID: occurrence.ID, AgentID: occurrence.AgentID, LeaseToken: occurrence.LeaseToken,
			})
			if err != nil {
				s.logger.Error("scheduler: renew lease", zap.String("occurrence", pgUUID(occurrence.ID).String()), zap.Error(err))
				continue
			}
			if updated == 0 {
				s.logger.Warn("scheduler: delivery lease lost", zap.String("occurrence", pgUUID(occurrence.ID).String()))
				cancel()
				return
			}
		}
	}
}

func (s *Scheduler) recordFailure(ctx context.Context, occurrence dbq.AgentScheduledFire, deliveryErr error) {
	message := deliveryErr.Error()
	if len(message) > maxScheduleErrorBytes {
		message = message[:maxScheduleErrorBytes]
	}
	q := dbq.New(s.db.Pool())
	if occurrence.Attempt >= occurrence.MaxAttempts {
		updated, err := q.FailScheduledFire(ctx, dbq.FailScheduledFireParams{
			LastError: message, ID: occurrence.ID, AgentID: occurrence.AgentID, LeaseToken: occurrence.LeaseToken,
		})
		if err != nil || updated == 0 {
			s.logger.Error("scheduler: terminal failure acknowledgement", zap.Error(err))
		}
		return
	}
	backoff := int32(5 << min(occurrence.Attempt-1, 6))
	updated, err := q.RetryScheduledFire(ctx, dbq.RetryScheduledFireParams{
		BackoffSeconds: backoff, LastError: message, ID: occurrence.ID, AgentID: occurrence.AgentID, LeaseToken: occurrence.LeaseToken,
	})
	if err != nil || updated == 0 {
		s.logger.Error("scheduler: retry acknowledgement", zap.Error(err))
	}
}

// ReconcileAgent transactionally retains matching cron occurrences, cancels
// stale ones, seeds missing occurrences, and orphans removed one-shot handlers.
func (s *Scheduler) ReconcileAgent(ctx context.Context, agentID uuid.UUID, definitions []wire.ScheduleHandlerDef) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, toPgUUID(agentID)); err != nil {
		return err
	}
	definitionSlugs := make([]string, len(definitions))
	seen := make(map[string]struct{}, len(definitions))
	for i, definition := range definitions {
		if _, exists := seen[definition.Slug]; exists {
			return fmt.Errorf("duplicate schedule handler %q", definition.Slug)
		}
		seen[definition.Slug] = struct{}{}
		if definition.Kind != "cron" && definition.Kind != "schedule" {
			return fmt.Errorf("invalid schedule handler kind %q", definition.Kind)
		}
		if definition.Kind == "cron" {
			if _, err := cronParser.Parse(definition.Recurrence); err != nil {
				return fmt.Errorf("parse cron %s: %w", definition.Slug, err)
			}
		} else if definition.Recurrence != "" {
			return fmt.Errorf("one-shot schedule %s has recurrence", definition.Slug)
		}
		timeoutMs := definition.TimeoutMs
		if timeoutMs == 0 {
			timeoutMs = 120000
		}
		if timeoutMs < 0 {
			return fmt.Errorf("schedule %s has negative timeout", definition.Slug)
		}
		if err := q.UpsertScheduleHandler(ctx, dbq.UpsertScheduleHandlerParams{
			AgentID: toPgUUID(agentID), Slug: definition.Slug, Kind: definition.Kind,
			Recurrence: definition.Recurrence, TimeoutMs: timeoutMs, Description: definition.Description,
		}); err != nil {
			return err
		}
		definitionSlugs[i] = definition.Slug
	}
	if err := q.DeleteScheduleHandlersByAgentExcept(ctx, dbq.DeleteScheduleHandlersByAgentExceptParams{
		AgentID: toPgUUID(agentID), Slugs: definitionSlugs,
	}); err != nil {
		return err
	}
	handlers, err := q.ListScheduleHandlersByAgent(ctx, toPgUUID(agentID))
	if err != nil {
		return err
	}
	slugs := make([]string, len(handlers))
	crons := make(map[string]dbq.AgentScheduleHandler)
	for i, handler := range handlers {
		slugs[i] = handler.Slug
		if handler.Kind == "cron" && handler.Enabled {
			crons[handler.Slug] = handler
		}
	}
	if err := q.OrphanMissingScheduleFires(ctx, dbq.OrphanMissingScheduleFiresParams{AgentID: toPgUUID(agentID), Slugs: slugs}); err != nil {
		return err
	}
	pending, err := q.ListPendingCronFires(ctx, toPgUUID(agentID))
	if err != nil {
		return err
	}
	retained := make(map[string]bool)
	for _, occurrence := range pending {
		handler, ok := crons[occurrence.Slug]
		if ok && handler.Recurrence == occurrence.Recurrence && !retained[occurrence.Slug] {
			retained[occurrence.Slug] = true
			continue
		}
		if _, err := q.CancelScheduledFire(ctx, dbq.CancelScheduledFireParams{ID: occurrence.ID, AgentID: occurrence.AgentID}); err != nil {
			return err
		}
	}
	for slug, handler := range crons {
		if retained[slug] {
			continue
		}
		next, err := nextFire(handler.Recurrence, time.Now())
		if err != nil {
			return fmt.Errorf("parse cron %s: %w", slug, err)
		}
		if _, err := q.InsertScheduledFire(ctx, dbq.InsertScheduledFireParams{
			ID: toPgUUID(uuid.New()), AgentID: toPgUUID(agentID), Source: "cron", Slug: slug,
			FireAt: pgTimestamp(next), Recurrence: handler.Recurrence, TimeoutMs: handler.TimeoutMs, MaxAttempts: schedulerMaxAttempts,
		}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func nextFire(expression string, after time.Time) (time.Time, error) {
	schedule, err := cronParser.Parse(expression)
	if err != nil {
		return time.Time{}, err
	}
	return schedule.Next(after), nil
}

func pgTimestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC().Truncate(time.Microsecond), Valid: true}
}
