// Package runs owns the list / get / log / cancel operations for the
// runs table. Every operation gates on the caller's access to the run's
// agent: reads require agent membership (AccessUser); cancel requires
// agent-admin or ownership of the run's conversation (web prompt runs).
package runs

import (
	"context"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
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
// A zero cursor returns the newest page. Requires agent membership.
func (s *Service) List(ctx context.Context, p authz.Principal, agentID uuid.UUID, cursor time.Time, limit int32) (ListResult, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentRunView, agentID); err != nil {
		return ListResult{}, err
	}
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
// when the run row is missing. Requires membership of the run's agent.
// Best-effort messages load: a query failure there returns an empty slice.
func (s *Service) Get(ctx context.Context, p authz.Principal, runID uuid.UUID) (GetResult, error) {
	q := dbq.New(s.db.Pool())
	run, err := q.GetRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		return GetResult{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentRunView, uuid.UUID(run.AgentID.Bytes)); err != nil {
		return GetResult{}, err
	}
	msgs, _ := q.ListMessagesByRun(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	return GetResult{Run: run, Messages: msgs}, nil
}

// Logs returns the captured stdout for a run. ErrNotFound for a missing
// run. Requires membership of the run's agent.
func (s *Service) Logs(ctx context.Context, p authz.Principal, runID uuid.UUID) (string, error) {
	q := dbq.New(s.db.Pool())
	run, err := q.GetRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		return "", service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentRunView, uuid.UUID(run.AgentID.Bytes)); err != nil {
		return "", err
	}
	return run.StdoutLog, nil
}

// Cancel signals the dispatcher (best-effort breaking the agent's
// streaming response) and then marks the row cancelled in the DB,
// idempotent with the agent's own r.Complete write. ErrNotFound for a
// missing run; ErrConflict if the run is already in a terminal state.
// Authorized for agent admins, or the owner of the run's conversation
// when the run was a web prompt (so a user can stop their own run).
func (s *Service) Cancel(ctx context.Context, p authz.Principal, runID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	run, err := q.GetRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := s.authorizeCancel(ctx, q, p, run); err != nil {
		return err
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

// authorizeCancel permits agent admins, plus the owner of the run's
// conversation when the run was a web prompt. Web prompt runs store the
// conversation ID in trigger_ref; the dispatcher's in-memory cancel
// registry carries no caller identity, so ownership is resolved from the
// run row here. Cron/webhook/bridge runs have no user owner and stay
// admin-only.
func (s *Service) authorizeCancel(ctx context.Context, q *dbq.Queries, p authz.Principal, run dbq.Run) error {
	if !p.IsAuthenticatedUser() {
		return service.ErrUnauthorized
	}
	agentID := uuid.UUID(run.AgentID.Bytes)
	if authz.AccessAtLeast(p.EffectiveAgentAccess(ctx, q, agentID), agentsdk.AccessAdmin) {
		return nil
	}
	if run.TriggerType == "prompt" {
		if convID, err := uuid.Parse(run.TriggerRef); err == nil {
			conv, err := q.GetConversationByID(ctx, pgtype.UUID{Bytes: convID, Valid: true})
			if err == nil && conv.UserID.Valid && uuid.UUID(conv.UserID.Bytes) == p.UserID {
				return nil
			}
		}
	}
	return service.ErrForbidden
}

// MarkTimedOut force-completes a run with status=timeout when a
// streaming-response finalizer ends without the agent writing a
// terminal status itself. The UPDATE is CAS-guarded by
// `WHERE status='running'`, so the agent's authoritative terminal
// write — if it lands — wins this race; otherwise the row reflects
// that nobody closed it. Also rolls up llm_usage ledger rows
// (idempotent with the agent-side aggregation).
//
// Internal-only: invoked by airlock's request-finalizer goroutines
// after the HTTP response has returned. No Principal because the
// operation has no user-facing access decision — the CAS is the
// sole correctness guard.
func (s *Service) MarkTimedOut(ctx context.Context, runID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	pgID := pgtype.UUID{Bytes: runID, Valid: true}
	if err := q.UpdateRunStatus(ctx, dbq.UpdateRunStatusParams{
		ID:     pgID,
		Status: "timeout",
	}); err != nil {
		s.logger.Error("update run status to timeout", zap.Error(err))
		return err
	}
	if err := q.UpdateRunLLMStats(ctx, pgID); err != nil {
		s.logger.Error("aggregate run llm stats", zap.Error(err))
		return err
	}
	return nil
}
