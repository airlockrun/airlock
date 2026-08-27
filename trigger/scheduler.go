package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

var (
	cronParser = cron.NewParser(
		cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
	)
	jobCronSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	jobCronHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ErrInvalidJobCron  = errors.New("invalid job cron declaration")
	ErrStaleJobCrons   = errors.New("stale job cron manifest")
)

const (
	schedulerPollInterval      = 5 * time.Second
	schedulerBatchSize         = 32
	maxJobCronDescriptionBytes = 4096
	maxJobCronScheduleBytes    = 1024
	maxJobCronInputBytes       = 64 * 1024
)

// Scheduler materializes due cron declarations into the durable job queue.
// PostgreSQL row locks serialize occurrences across Airlock replicas.
type Scheduler struct {
	db           *db.DB
	jobWake      func()
	logger       *zap.Logger
	wake         chan struct{}
	pollInterval time.Duration
}

func NewScheduler(database *db.DB, jobWake func(), logger *zap.Logger) *Scheduler {
	if database == nil {
		panic("trigger: scheduler db is required")
	}
	if jobWake == nil {
		panic("trigger: scheduler job wake is required")
	}
	if logger == nil {
		panic("trigger: scheduler logger is required")
	}
	return &Scheduler{
		db: database, jobWake: jobWake, logger: logger,
		wake: make(chan struct{}, 1), pollInterval: schedulerPollInterval,
	}
}

// Wake requests an immediate poll. Periodic polling remains the correctness
// path, so concurrent notifications can be coalesced.
func (s *Scheduler) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Scheduler) Run(ctx context.Context) error {
	s.logger.Info("scheduler started", zap.Duration("poll", s.pollInterval))
	s.poll(ctx)
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.poll(ctx)
		case <-s.wake:
			s.poll(ctx)
		}
	}
}

func (s *Scheduler) poll(ctx context.Context) {
	materialized := 0
	for materialized < schedulerBatchSize {
		count, err := s.materializeDueLimit(ctx, int32(schedulerBatchSize-materialized))
		if err != nil {
			s.logger.Error("scheduler: materialize due crons", zap.Error(err))
			return
		}
		if count == 0 {
			break
		}
		materialized += count
	}
	if materialized > 0 {
		s.jobWake()
	}
}

func (s *Scheduler) materializeDue(ctx context.Context) (int, error) {
	return s.materializeDueLimit(ctx, schedulerBatchSize)
}

func (s *Scheduler) materializeDueLimit(ctx context.Context, limit int32) (int, error) {
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
	for _, declaration := range due {
		occurrence := declaration.NextFireAt.Time
		next, err := nextFire(declaration.Schedule, occurrence)
		if err != nil {
			return 0, fmt.Errorf("parse cron %s: %w", declaration.Slug, err)
		}
		if _, err := q.InsertAgentJobFromCron(ctx, dbq.InsertAgentJobFromCronParams{
			JobID:                   toPgUUID(uuid.New()),
			ScheduledAt:             pgTimestamp(occurrence),
			InitiatorKind:           "system",
			InitiatorUserID:         pgtype.UUID{},
			InitiatorConversationID: pgtype.UUID{},
			InitiatorAccess:         "public",
			CronID:                  declaration.ID,
		}); err != nil {
			return 0, fmt.Errorf("insert job for cron %s: %w", declaration.Slug, err)
		}
		advanced, err := q.AdvanceAgentJobCron(ctx, dbq.AdvanceAgentJobCronParams{
			NextFireAt:      pgTimestamp(next),
			OccurrenceAt:    pgTimestamp(occurrence),
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

// ReconcileAgent replaces one runtime generation's cron declarations while
// retaining operator state and the next occurrence for unchanged work.
func (s *Scheduler) ReconcileAgent(ctx context.Context, agentID uuid.UUID, tokenVersion int64, definitions []wire.JobCronDef) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin job cron reconciliation: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := s.ReconcileAgentTx(ctx, tx, agentID, tokenVersion, definitions); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit job cron reconciliation: %w", err)
	}
	s.Wake()
	return nil
}

// ReconcileAgentTx reconciles cron declarations as part of a larger manifest
// transaction. The caller commits the transaction and wakes the scheduler.
func (s *Scheduler) ReconcileAgentTx(ctx context.Context, tx pgx.Tx, agentID uuid.UUID, tokenVersion int64, definitions []wire.JobCronDef) error {
	normalized, err := normalizeJobCronDefinitions(definitions)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJobCron, err)
	}
	q := dbq.New(tx)
	pgAgentID := toPgUUID(agentID)
	agent, err := q.GetAgentByIDForUpdate(ctx, pgAgentID)
	if err != nil {
		return fmt.Errorf("lock agent for job cron reconciliation: %w", err)
	}
	if tokenVersion <= 0 || agent.AgentTokenVersion != tokenVersion || (agent.Status != "active" && agent.Status != "building") {
		return fmt.Errorf("%w: authenticated runtime generation is no longer active", ErrStaleJobCrons)
	}
	now := time.Now().UTC()
	slugs := make([]string, len(normalized))
	for i, definition := range normalized {
		handler, err := q.GetAgentJobHandlerForEnqueue(ctx, dbq.GetAgentJobHandlerForEnqueueParams{
			AgentID: pgAgentID, HandlerName: definition.HandlerName, HandlerVersion: definition.HandlerVersion,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: job cron %q targets a handler outside the active runtime generation", ErrInvalidJobCron, definition.Slug)
			}
			return fmt.Errorf("get handler for job cron %q: %w", definition.Slug, err)
		}
		if handler.InputSchemaHash != definition.InputSchemaHash || handler.OutputSchemaHash != definition.OutputSchemaHash {
			return fmt.Errorf("%w: job cron %q does not match handler %s@v%d", ErrInvalidJobCron, definition.Slug, definition.HandlerName, definition.HandlerVersion)
		}
		next, err := nextFire(definition.Schedule, now)
		if err != nil {
			return fmt.Errorf("parse cron %s: %w", definition.Slug, err)
		}
		if _, err := q.UpsertAgentJobCron(ctx, dbq.UpsertAgentJobCronParams{
			AgentID:           pgAgentID,
			Slug:              definition.Slug,
			Schedule:          definition.Schedule,
			Description:       definition.Description,
			HandlerName:       definition.HandlerName,
			HandlerVersion:    definition.HandlerVersion,
			InputSchemaHash:   definition.InputSchemaHash,
			OutputSchemaHash:  definition.OutputSchemaHash,
			InputPayload:      definition.Input,
			AgentTokenVersion: tokenVersion,
			NextFireAt:        pgTimestamp(next),
		}); err != nil {
			return fmt.Errorf("upsert job cron %q: %w", definition.Slug, err)
		}
		slugs[i] = definition.Slug
	}
	if err := q.DeleteAgentJobCronsByAgentExcept(ctx, dbq.DeleteAgentJobCronsByAgentExceptParams{
		AgentID: pgAgentID, Slugs: slugs,
	}); err != nil {
		return fmt.Errorf("delete absent job crons: %w", err)
	}
	return nil
}

func normalizeJobCronDefinitions(definitions []wire.JobCronDef) ([]wire.JobCronDef, error) {
	normalized := make([]wire.JobCronDef, len(definitions))
	seen := make(map[string]struct{}, len(definitions))
	for i, definition := range definitions {
		if len(definition.Slug) > 63 || !jobCronSlugPattern.MatchString(definition.Slug) {
			return nil, fmt.Errorf("job cron slug %q must be lowercase snake_case with at most 63 characters", definition.Slug)
		}
		if _, exists := seen[definition.Slug]; exists {
			return nil, fmt.Errorf("duplicate job cron %q", definition.Slug)
		}
		seen[definition.Slug] = struct{}{}
		if strings.TrimSpace(definition.Schedule) == "" || len(definition.Schedule) > maxJobCronScheduleBytes {
			return nil, fmt.Errorf("job cron %q has an invalid schedule", definition.Slug)
		}
		if _, err := cronParser.Parse(definition.Schedule); err != nil {
			return nil, fmt.Errorf("parse cron %s: %w", definition.Slug, err)
		}
		if strings.TrimSpace(definition.Description) == "" || len(definition.Description) > maxJobCronDescriptionBytes {
			return nil, fmt.Errorf("job cron %q description must be nonblank and at most %d bytes", definition.Slug, maxJobCronDescriptionBytes)
		}
		if len(definition.HandlerName) > 63 || !jobCronSlugPattern.MatchString(definition.HandlerName) || definition.HandlerVersion <= 0 {
			return nil, fmt.Errorf("job cron %q has an invalid handler target", definition.Slug)
		}
		if !jobCronHashPattern.MatchString(definition.InputSchemaHash) || !jobCronHashPattern.MatchString(definition.OutputSchemaHash) {
			return nil, fmt.Errorf("job cron %q has invalid schema hashes", definition.Slug)
		}
		input, err := canonicalJobCronInput(definition.Input)
		if err != nil {
			return nil, fmt.Errorf("job cron %q input: %w", definition.Slug, err)
		}
		definition.Input = input
		normalized[i] = definition
	}
	return normalized, nil
}

func canonicalJobCronInput(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxJobCronInputBytes {
		return nil, fmt.Errorf("must be a JSON object no larger than %d bytes", maxJobCronInputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, errors.New("must be a JSON object")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("contains trailing data")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxJobCronInputBytes {
		return nil, fmt.Errorf("canonical input exceeds %d bytes", maxJobCronInputBytes)
	}
	return encoded, nil
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
