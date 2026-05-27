// Package runs owns the list / get / log / cancel operations for the
// runs table. Today no per-run authorization gate is applied — runs
// are addressable by ID for any authenticated user. Preserved.
package runs

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Dispatcher is the subset of *trigger.Dispatcher Cancel uses. An
// interface so the runsHandler / tests can swap in stubs.
type Dispatcher interface {
	CancelRun(runID uuid.UUID) bool
}

type Service struct {
	db         *db.DB
	dispatcher Dispatcher
	logger     *zap.Logger
}

func New(d *db.DB, dispatcher Dispatcher, logger *zap.Logger) *Service {
	if d == nil {
		panic("runs: db is required")
	}
	if dispatcher == nil {
		panic("runs: dispatcher is required")
	}
	if logger == nil {
		panic("runs: logger is required")
	}
	return &Service{db: d, dispatcher: dispatcher, logger: logger}
}

// ListResult bundles a page of runs with the cursor for the next page.
// NextCursor is the zero time when there is no next page.
type ListResult struct {
	Runs       []dbq.Run
	NextCursor time.Time
}

// List returns up to `limit` runs for the agent, paginated by started_at.
// A zero cursor returns the newest page.
func (s *Service) List(ctx context.Context, agentID uuid.UUID, cursor time.Time, limit int32) (ListResult, error) {
	q := dbq.New(s.db.Pool())
	var cur pgtype.Timestamptz
	if !cursor.IsZero() {
		cur = pgtype.Timestamptz{Time: cursor, Valid: true}
	}
	rows, err := q.ListRunsByAgent(ctx, dbq.ListRunsByAgentParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
		Cursor:  cur,
		Lim:     limit,
	})
	if err != nil {
		s.logger.Error("list runs", zap.Error(err))
		return ListResult{}, err
	}
	out := ListResult{Runs: rows}
	if len(rows) == int(limit) {
		out.NextCursor = rows[len(rows)-1].StartedAt.Time
	}
	return out, nil
}

// GetResult bundles a run with its produced messages, in the shape the
// run detail page needs.
type GetResult struct {
	Run      dbq.Run
	Messages []dbq.AgentMessage
}

// Get returns one run and the messages produced during it. ErrNotFound
// when the run row is missing. Best-effort messages load: a query
// failure there returns an empty slice (matching today).
func (s *Service) Get(ctx context.Context, runID uuid.UUID) (GetResult, error) {
	q := dbq.New(s.db.Pool())
	run, err := q.GetRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		return GetResult{}, service.ErrNotFound
	}
	msgs, _ := q.ListMessagesByRun(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	return GetResult{Run: run, Messages: msgs}, nil
}

// Logs returns the captured stdout for a run. ErrNotFound for a missing run.
func (s *Service) Logs(ctx context.Context, runID uuid.UUID) (string, error) {
	q := dbq.New(s.db.Pool())
	run, err := q.GetRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		return "", service.ErrNotFound
	}
	return run.StdoutLog, nil
}

// Cancel signals the dispatcher (best-effort breaking the agent's
// streaming response) and then marks the row cancelled in the DB,
// idempotent with the agent's own r.Complete write. ErrNotFound for a
// missing run; ErrConflict if the run is already in a terminal state.
func (s *Service) Cancel(ctx context.Context, runID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	run, err := q.GetRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if run.Status != "running" {
		return service.ErrConflict
	}
	s.dispatcher.CancelRun(runID)
	_ = q.UpdateRunComplete(ctx, dbq.UpdateRunCompleteParams{
		ID:           pgtype.UUID{Bytes: runID, Valid: true},
		Status:       "cancelled",
		ErrorMessage: "cancelled by user",
	})
	return nil
}
