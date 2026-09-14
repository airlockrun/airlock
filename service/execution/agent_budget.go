package execution

import (
	"context"
	"errors"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrAgentBudget = errors.New("agent budget exceeded")

var ErrAgentUsageUnavailable = errors.New("model did not report input and output usage required by the agent token budget")

// ReserveAgentTaskStep reserves one reasoning turn for the exact live owner.
// Native callbacks and hosted agent models share the same root accounting.
func ReserveAgentTaskStep(ctx context.Context, database *db.DB, appID, runID, ownerToken uuid.UUID) error {
	if database == nil {
		panic("execution: database is required")
	}
	if appID == uuid.Nil || runID == uuid.Nil || ownerToken == uuid.Nil {
		return service.ErrInvalidInput
	}
	tx, err := database.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := q.LockAgentTaskScheduler(ctx); err != nil {
		return err
	}
	if _, err := Resolve(WithRuntimeOwner(ctx, runID, ownerToken), q, appID, runID); err != nil {
		return err
	}
	call, err := q.LockAgentTaskOwner(ctx, dbq.LockAgentTaskOwnerParams{ID: pgID(runID), OwnerToken: pgID(ownerToken)})
	if err != nil {
		return err
	}
	if call.AgentID != pgID(appID) || call.OwnerToken != pgID(ownerToken) {
		return service.ErrForbidden
	}
	root, err := q.GetAgentTaskCall(ctx, call.RootID)
	if err != nil {
		return err
	}
	for _, budget := range []dbq.AgentTaskCall{call, root} {
		if budget.StepLimit > 0 && budget.Steps >= budget.StepLimit || budget.TokenLimit > 0 && budget.Tokens >= budget.TokenLimit || budget.Deadline.Valid && !time.Now().Before(budget.Deadline.Time) || budget.CancelRequestedAt.Valid || budget.CompletedAt.Valid {
			return ErrAgentBudget
		}
	}
	if err := q.ChargeAgentTaskBudget(ctx, dbq.ChargeAgentTaskBudgetParams{ID: call.ID, RootID: call.RootID, Steps: 1}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecordAgentTaskUsage settles one model request exactly once. A historical
// claim can report incurred usage after lease loss, but cannot authorize another
// model/tool call. The run/session/token binding is verified from durable claims.
func RecordAgentTaskUsage(ctx context.Context, database *db.DB, appID, runID, ownerToken, requestID uuid.UUID, tokens int64, reported bool) error {
	if database == nil {
		panic("execution: database is required")
	}
	if appID == uuid.Nil || runID == uuid.Nil || ownerToken == uuid.Nil || requestID == uuid.Nil || tokens < 0 {
		return service.ErrInvalidInput
	}
	tx, err := database.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := q.LockAgentTaskScheduler(ctx); err != nil {
		return err
	}
	n, err := q.RecordAgentTaskUsage(ctx, dbq.RecordAgentTaskUsageParams{AgentID: pgID(appID), RunID: pgID(runID), OwnerToken: pgID(ownerToken), RequestID: pgID(requestID), Tokens: tokens, Reported: reported})
	if err != nil {
		return err
	}
	if n == 0 {
		prior, err := q.GetAgentTaskUsage(ctx, dbq.GetAgentTaskUsageParams{RequestID: pgID(requestID), AgentID: pgID(appID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return service.ErrForbidden
		}
		if err != nil {
			return err
		}
		if prior.RunID != pgID(runID) || prior.OwnerToken != pgID(ownerToken) || prior.Tokens != tokens || prior.Reported != reported {
			return service.ErrConflict
		}
	}
	call, err := q.GetAgentTaskCall(ctx, pgID(runID))
	if err != nil {
		return err
	}
	if n == 1 {
		if err := q.ChargeAgentTaskBudget(ctx, dbq.ChargeAgentTaskBudgetParams{ID: call.ID, RootID: call.RootID, Tokens: tokens}); err != nil {
			return err
		}
	}
	root, err := q.GetAgentTaskCall(ctx, call.RootID)
	if err != nil {
		return err
	}
	if !reported && (call.TokenLimit > 0 || root.TokenLimit > 0) {
		id := call.ID
		if root.TokenLimit > 0 {
			id = root.ID
		}
		if err := q.RequestAgentTaskFailure(ctx, dbq.RequestAgentTaskFailureParams{ID: id, Error: ErrAgentUsageUnavailable.Error()}); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return ErrAgentUsageUnavailable
	}
	return tx.Commit(ctx)
}
