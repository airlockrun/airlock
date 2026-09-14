package execution

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AppOrigin records an app-owned trigger against its live authenticated runtime
// generation. Host schedulers use the generation locked with their cron record.
func AppOrigin(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, generation int64, ingress string) (dbq.ExecutionOrigin, error) {
	if ingress != "app" && ingress != "webhook" && ingress != "cron" {
		return dbq.ExecutionOrigin{}, service.ErrInvalidInput
	}
	a, err := q.GetAgentByID(ctx, pgID(agentID))
	if err != nil || generation <= 0 || a.AgentTokenVersion != generation || a.Status != "active" && a.Status != "building" {
		return dbq.ExecutionOrigin{}, service.ErrUnauthorized
	}
	return q.CreateExecutionOrigin(ctx, dbq.CreateExecutionOriginParams{ID: pgID(uuid.New()), AgentID: a.ID, Ingress: ingress, Actor: "app", CredentialProfile: "none", RuntimeGeneration: pgtype.Int8{Int64: generation, Valid: true}})
}

// AdmitApp cannot borrow a human identity, conversation, or access assertion.
func (s *Service) AdmitApp(ctx context.Context, agentID uuid.UUID, generation int64, kind Kind, ref string, input json.RawMessage) (dbq.Run, error) {
	if kind != App && kind != Webhook || !json.Valid(input) {
		return dbq.Run{}, service.ErrInvalidInput
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.Run{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	a, err := q.GetAgentByIDForUpdate(ctx, pgID(agentID))
	if err != nil {
		return dbq.Run{}, err
	}
	if err := RequireRuntimeProtocol(ctx, q, agentID); err != nil {
		return dbq.Run{}, err
	}
	o, err := AppOrigin(ctx, q, agentID, generation, string(kind))
	if err != nil {
		return dbq.Run{}, err
	}
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{AgentID: a.ID, OriginID: o.ID, ExecutionKind: string(kind), TriggerType: string(kind), TriggerRef: ref, SourceRef: a.SourceRef, InputPayload: input, CallerAccess: "admin"})
	if err != nil {
		return dbq.Run{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.Run{}, err
	}
	return run, nil
}

// AdmitJob atomically binds exactly one token-fenced delivery attempt to a run.
// The immutable job origin retains its ingress independently of execution kind.
func (s *Service) AdmitJob(ctx context.Context, jobID uuid.UUID, attemptNumber int32, leaseToken uuid.UUID) (dbq.Run, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.Run{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	job, err := q.GetAgentJobByID(ctx, pgID(jobID))
	if err != nil {
		return dbq.Run{}, err
	}
	a, err := q.GetAgentByIDForUpdate(ctx, job.AgentID)
	if err != nil {
		return dbq.Run{}, err
	}
	attempt, err := q.LockExecutionJobAttempt(ctx, dbq.LockExecutionJobAttemptParams{JobID: job.ID, AttemptNumber: attemptNumber, LeaseToken: pgID(leaseToken)})
	if err != nil || a.AgentTokenVersion != attempt.RuntimeGeneration {
		return dbq.Run{}, service.ErrConflict
	}
	o, err := q.GetExecutionOrigin(ctx, job.OriginID)
	if err != nil || o.Actor == "unknown" {
		return dbq.Run{}, service.ErrUnauthorized
	}
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{AgentID: a.ID, OriginID: o.ID, ExecutionKind: string(Job), TriggerType: "job", TriggerRef: jobID.String(), SourceRef: a.SourceRef, InputPayload: job.InputPayload, CallerAccess: job.InitiatorAccess, CallerUserID: o.UserID, CallerConversationID: o.ConversationID, BridgeID: o.BridgeID})
	if err != nil {
		return dbq.Run{}, err
	}
	if n, err := q.StartAgentJobAttempt(ctx, dbq.StartAgentJobAttemptParams{RunID: run.ID, JobID: job.ID, AttemptNumber: attempt.AttemptNumber, LeaseOwner: attempt.LeaseOwner, LeaseToken: attempt.LeaseToken}); err != nil || n != 1 {
		return dbq.Run{}, service.ErrConflict
	}
	if _, err := Resolve(ctx, q, uuid.UUID(a.ID.Bytes), uuid.UUID(run.ID.Bytes)); err != nil {
		if !errors.Is(err, auth.ErrRunAuthorityRevoked) {
			return dbq.Run{}, err
		}
		if _, cancelErr := q.CancelExecutionJob(ctx, run.ID); cancelErr != nil {
			return dbq.Run{}, cancelErr
		}
		if _, finishErr := q.FailRunDispatch(ctx, dbq.FailRunDispatchParams{ID: run.ID, ErrorMessage: "execution authority is no longer valid"}); finishErr != nil {
			return dbq.Run{}, finishErr
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return dbq.Run{}, commitErr
		}
		return run, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.Run{}, err
	}
	return run, nil
}
