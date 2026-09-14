// Package chatruns owns durable hosted-run leases. Every writer fences against
// the same lease token; process-local cancellation is only a latency optimization.
package chatruns

import (
	"context"
	"errors"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrLeaseLost = errors.New("chat run ownership lost")

type Service struct{ db *db.DB }

func New(database *db.DB) *Service {
	if database == nil {
		panic("chatruns: database is required")
	}
	return &Service{db: database}
}

// Acquire requires the caller identity to match the persisted run. An expired
// owner must be settled by Recover before a successor can acquire the thread.
func (s *Service) Acquire(ctx context.Context, p authz.Principal, agentID, runID uuid.UUID) (uuid.UUID, error) {
	q := dbq.New(s.db.Pool())
	if _, err := execution.Principal(ctx, q, p); err != nil {
		return uuid.Nil, err
	}
	if _, err := execution.Resolve(ctx, q, agentID, runID); err != nil {
		return uuid.Nil, err
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentRuntimeInvoke, agentID); err != nil {
		return uuid.Nil, err
	}
	run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: pgID(runID), AgentID: pgID(agentID)})
	if err != nil {
		return uuid.Nil, err
	}
	if !run.CallerConversationID.Valid || run.RuntimeOwnerToken.Valid ||
		(run.CallerUserID.Valid && uuid.UUID(run.CallerUserID.Bytes) != p.UserID) ||
		(!run.CallerUserID.Valid && p.Kind != authz.KindAnonymousUser) {
		return uuid.Nil, service.ErrForbidden
	}
	token := uuid.New()
	rows, err := q.AcquireConversationRunLease(ctx, dbq.AcquireConversationRunLeaseParams{
		ConversationID: run.CallerConversationID, RunID: run.ID, OwnerToken: pgID(token),
	})
	if err != nil {
		return uuid.Nil, err
	}
	if rows != 1 {
		return uuid.Nil, service.ErrConflict
	}
	return token, nil
}

// KeepAlive cancels execution on cancellation, lease expiry, or a database error.
// Its return value must be called and awaited before releasing the lease.
func (s *Service) KeepAlive(ctx context.Context, runID, token uuid.UUID, cancel context.CancelFunc) func() {
	if cancel == nil || runID == uuid.Nil || token == uuid.Nil {
		panic("chatruns: run, token and cancel are required")
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				check, end := context.WithTimeout(ctx, 5*time.Second)
				q := dbq.New(s.db.Pool())
				run, err := q.GetRunByID(check, pgID(runID))
				if err == nil {
					_, err = execution.Resolve(check, q, uuid.UUID(run.AgentID.Bytes), runID)
				}
				var rows int64
				if err == nil {
					rows, err = q.RenewConversationRunLease(check, dbq.RenewConversationRunLeaseParams{RunID: pgID(runID), OwnerToken: pgID(token)})
				}
				end()
				if err != nil || rows != 1 {
					cancel()
					return
				}
			}
		}
	}()
	return func() { close(stop); <-done }
}

// Complete commits terminal state, recovery writes, and lease release together.
// settle may only use the supplied transaction-scoped queries.
func (s *Service) Complete(ctx context.Context, runID, token uuid.UUID, status, errorMessage string, checkpoint []byte, settle func(context.Context, *dbq.Queries) error) error {
	if settle == nil {
		panic("chatruns: settlement is required")
	}
	if status != "success" && status != "error" && status != "suspended" && status != "cancelled" && status != "timeout" {
		return service.ErrInvalidInput
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	lease, err := q.LockFinishingConversationRunLease(ctx, dbq.LockFinishingConversationRunLeaseParams{RunID: pgID(runID), OwnerToken: pgID(token)})
	if err != nil {
		return ErrLeaseLost
	}
	if lease.CancelRequested || lease.Status == "cancelled" {
		status, errorMessage, checkpoint = "cancelled", "cancelled by user", nil
	}
	stored, err := q.GetRunByID(ctx, pgID(runID))
	if err != nil {
		return err
	}
	if _, err := execution.Resolve(ctx, q, uuid.UUID(stored.AgentID.Bytes), runID); err != nil {
		status, errorMessage, checkpoint = "cancelled", "execution authority is no longer valid", nil
	}
	rows, err := q.CompleteHostedRun(ctx, dbq.CompleteHostedRunParams{RunID: pgID(runID), OwnerToken: pgID(token), Status: status, ErrorMessage: errorMessage, Checkpoint: checkpoint, ErrorKind: ""})
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrLeaseLost
	}
	if err := settle(ctx, q); err != nil {
		return err
	}
	if err := q.UpdateRunLLMStats(ctx, pgID(runID)); err != nil {
		return err
	}
	if _, err := q.ReleaseConversationRunLease(ctx, dbq.ReleaseConversationRunLeaseParams{RunID: pgID(runID), OwnerToken: pgID(token)}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Recover is replica-safe and never touches a live lease. Settlement must succeed
// before another run can acquire the conversation.
func (s *Service) Recover(ctx context.Context, settle func(context.Context, *dbq.Queries, uuid.UUID) error) error {
	if settle == nil {
		panic("chatruns: recovery settlement is required")
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	leases, err := q.ListExpiredConversationRunLeases(ctx)
	if err != nil {
		return err
	}
	for _, lease := range leases {
		if _, err := q.CompleteHostedRun(ctx, dbq.CompleteHostedRunParams{RunID: lease.RunID, OwnerToken: lease.OwnerToken, Status: "error", ErrorMessage: "chat runtime lease expired", ErrorKind: "platform"}); err != nil {
			return err
		}
		if err := settle(ctx, q, uuid.UUID(lease.RunID.Bytes)); err != nil {
			return err
		}
		if err := q.UpdateRunLLMStats(ctx, lease.RunID); err != nil {
			return err
		}
		if _, err := q.ReleaseConversationRunLease(ctx, dbq.ReleaseConversationRunLeaseParams{RunID: lease.RunID, OwnerToken: lease.OwnerToken}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func pgID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
