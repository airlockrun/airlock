package trigger

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

// cronParser supports both standard 5-field and optional-second 6-field expressions.
var cronParser = cron.NewParser(
	cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
)

// Scheduler manages cron schedules for all active agents.
type Scheduler struct {
	cron       *cron.Cron
	dispatcher *Dispatcher
	db         *db.DB
	logger     *zap.Logger
	mu         sync.Mutex
	entries    map[uuid.UUID][]cron.EntryID // agent_cron.id → cron entry IDs
}

// NewScheduler creates a Scheduler.
func NewScheduler(dispatcher *Dispatcher, db *db.DB, logger *zap.Logger) *Scheduler {
	return &Scheduler{
		cron:       cron.New(cron.WithParser(cronParser)),
		dispatcher: dispatcher,
		db:         db,
		logger:     logger,
		entries:    make(map[uuid.UUID][]cron.EntryID),
	}
}

// Start loads all enabled crons from the database and starts the scheduler.
func (s *Scheduler) Start(ctx context.Context) error {
	q := dbq.New(s.db.Pool())
	crons, err := q.ListAllEnabledCrons(ctx)
	if err != nil {
		return err
	}

	s.mu.Lock()
	for _, c := range crons {
		s.addCronLocked(c)
	}
	s.mu.Unlock()

	s.cron.Start()
	s.logger.Info("scheduler started", zap.Int("crons", len(crons)))
	return nil
}

// Stop gracefully stops the scheduler.
func (s *Scheduler) Stop() {
	s.cron.Stop()
}

// ReloadAgent reloads cron entries for a specific agent after a sync.
func (s *Scheduler) ReloadAgent(ctx context.Context, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	crons, err := q.ListCronsByAgent(ctx, toPgUUID(agentID))
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove existing entries for this agent.
	if entryIDs, ok := s.entries[agentID]; ok {
		for _, eid := range entryIDs {
			s.cron.Remove(eid)
		}
		delete(s.entries, agentID)
	}

	// Add new entries (only enabled ones).
	for _, c := range crons {
		if c.Enabled {
			s.addCronLocked(c)
		}
	}

	return nil
}

// addCronLocked adds a single cron entry. Must be called with s.mu held.
func (s *Scheduler) addCronLocked(c dbq.AgentCron) {
	agentID := pgUUID(c.AgentID)
	cronID := pgUUID(c.ID)
	cronName := c.Name
	timeout := time.Duration(c.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Minute
	}

	eid, err := s.cron.AddFunc(c.Schedule, func() {
		s.fireCron(agentID, cronID, cronName, timeout)
	})
	if err != nil {
		s.logger.Error("invalid cron schedule",
			zap.String("name", c.Name),
			zap.String("schedule", c.Schedule),
			zap.Error(err),
		)
		return
	}

	s.entries[agentID] = append(s.entries[agentID], eid)
}

// fireCron forwards a cron event to the agent container and updates last_fired_at.
func (s *Scheduler) fireCron(agentID, cronID uuid.UUID, cronName string, timeout time.Duration) {
	ctx := context.Background()
	s.logger.Info("firing cron", zap.String("agent", agentID.String()), zap.String("cron", cronName))

	rc, _, err := s.dispatcher.ForwardCron(ctx, agentID, cronName, timeout)
	if err != nil {
		s.logger.Error("cron fire failed",
			zap.String("agent", agentID.String()),
			zap.String("cron", cronName),
			zap.Error(err),
		)
		return
	}
	// Drain and close the response body — cron output is not delivered anywhere.
	io.Copy(io.Discard, rc)
	rc.Close()

	// Update last_fired_at.
	q := dbq.New(s.db.Pool())
	if err := q.UpdateCronLastFired(ctx, toPgUUID(cronID)); err != nil {
		s.logger.Error("update cron last_fired_at failed", zap.Error(err))
	}
}
