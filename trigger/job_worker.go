package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const (
	jobPollInterval  = 5 * time.Second
	jobLeaseDuration = 30 * time.Second
	jobGlobalLimit   = 32
	jobAgentLimit    = 8
	maxJobErrorBytes = 8192
)

type jobDispatcher interface {
	ForwardJob(context.Context, dbq.AgentJob, dbq.AgentJobAttempt) (wire.JobRunResponse, uuid.UUID, error)
}

// JobWorker claims durable attempts under shared PostgreSQL concurrency limits
// and keeps token-guarded leases alive while the agent handler is executing.
type JobWorker struct {
	dispatcher   jobDispatcher
	db           *db.DB
	logger       *zap.Logger
	owner        uuid.UUID
	wake         chan struct{}
	pollInterval time.Duration
	lease        time.Duration
	globalLimit  int64
	agentLimit   int64
	wg           sync.WaitGroup
}

func NewJobWorker(dispatcher *Dispatcher, database *db.DB, logger *zap.Logger) *JobWorker {
	return newJobWorker(dispatcher, database, logger, jobPollInterval, jobLeaseDuration, jobGlobalLimit, jobAgentLimit)
}

func newJobWorker(dispatcher jobDispatcher, database *db.DB, logger *zap.Logger, pollInterval, lease time.Duration, globalLimit, agentLimit int64) *JobWorker {
	if dispatcher == nil {
		panic("trigger: job worker dispatcher is required")
	}
	if database == nil {
		panic("trigger: job worker db is required")
	}
	if logger == nil {
		panic("trigger: job worker logger is required")
	}
	if pollInterval <= 0 || lease < 3*time.Second || globalLimit <= 0 || agentLimit <= 0 {
		panic("trigger: invalid job worker limits")
	}
	return &JobWorker{
		dispatcher: dispatcher, db: database, logger: logger, owner: uuid.New(), wake: make(chan struct{}, 1),
		pollInterval: pollInterval, lease: lease, globalLimit: globalLimit, agentLimit: agentLimit,
	}
}

// Wake requests an immediate poll. The durable queue and periodic polling are
// the correctness path, so coalescing concurrent wakeups is safe.
func (w *JobWorker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *JobWorker) Run(ctx context.Context) error {
	w.logger.Info("job worker started", zap.String("owner", w.owner.String()), zap.Duration("poll", w.pollInterval))
	w.poll(ctx)
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.wg.Wait()
			return nil
		case <-ticker.C:
			w.poll(ctx)
		case <-w.wake:
			w.poll(ctx)
		}
	}
}

func (w *JobWorker) poll(ctx context.Context) {
	if err := w.recoverExpired(ctx); err != nil {
		w.logger.Error("job worker: recover expired attempts", zap.Error(err))
		return
	}
	for ctx.Err() == nil {
		job, attempt, err := w.claim(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		if err != nil {
			w.logger.Error("job worker: claim", zap.Error(err))
			return
		}
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			w.deliver(ctx, job, attempt)
		}()
	}
}

func (w *JobWorker) claim(ctx context.Context) (dbq.AgentJob, dbq.AgentJobAttempt, error) {
	tx, err := w.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.AgentJob{}, dbq.AgentJobAttempt{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := q.LockAgentJobDispatch(ctx); err != nil {
		return dbq.AgentJob{}, dbq.AgentJobAttempt{}, err
	}
	agentID, err := q.LockAgentForDueJob(ctx, dbq.LockAgentForDueJobParams{
		GlobalLimit: w.globalLimit, AgentLimit: w.agentLimit,
	})
	if err != nil {
		return dbq.AgentJob{}, dbq.AgentJobAttempt{}, err
	}
	attempt, err := q.ClaimDueAgentJob(ctx, dbq.ClaimDueAgentJobParams{
		LeaseOwner: toPgUUID(w.owner), LeaseSeconds: int32(w.lease / time.Second),
		GlobalLimit: w.globalLimit, AgentLimit: w.agentLimit, AgentID: agentID,
	})
	if err != nil {
		return dbq.AgentJob{}, dbq.AgentJobAttempt{}, err
	}
	job, err := q.GetAgentJobByID(ctx, attempt.JobID)
	if err != nil {
		return dbq.AgentJob{}, dbq.AgentJobAttempt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.AgentJob{}, dbq.AgentJobAttempt{}, err
	}
	return job, attempt, nil
}

func (w *JobWorker) deliver(ctx context.Context, job dbq.AgentJob, attempt dbq.AgentJobAttempt) {
	deliveryCtx, cancel := context.WithCancel(ctx)
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		w.renewLease(deliveryCtx, attempt, cancel)
	}()
	result, _, deliveryErr := w.dispatcher.ForwardJob(deliveryCtx, job, attempt)
	cancel()
	<-renewed

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cleanupCancel()
	if deliveryErr != nil {
		if err := w.finish(cleanupCtx, attempt, "platform", nil, deliveryErr); err != nil && !errors.Is(err, ErrJobLeaseLost) {
			w.logger.Error("job worker: record delivery failure", zap.String("job", pgUUID(job.ID).String()), zap.Error(err))
		}
		return
	}
	switch result.Status {
	case "success":
		if len(result.Output) == 0 || !json.Valid(result.Output) {
			deliveryErr = errors.New("agent returned invalid job output")
			if err := w.finish(cleanupCtx, attempt, "platform", nil, deliveryErr); err != nil && !errors.Is(err, ErrJobLeaseLost) {
				w.logger.Error("job worker: record invalid response", zap.Error(err))
			}
			return
		}
		if err := w.finish(cleanupCtx, attempt, "success", result.Output, nil); err != nil && !errors.Is(err, ErrJobLeaseLost) {
			w.logger.Error("job worker: acknowledge success", zap.Error(err))
		}
	case "error", "timeout":
		message := result.Error
		if message == "" {
			message = "job handler returned " + result.Status
		}
		if err := w.finish(cleanupCtx, attempt, "agent", nil, errors.New(message)); err != nil && !errors.Is(err, ErrJobLeaseLost) {
			w.logger.Error("job worker: acknowledge handler failure", zap.Error(err))
		}
	case "retry":
		message := result.Error
		if message == "" {
			message = "job handler requested retry"
		}
		if err := w.finish(cleanupCtx, attempt, "deployment", nil, errors.New(message)); err != nil && !errors.Is(err, ErrJobLeaseLost) {
			w.logger.Error("job worker: acknowledge handler retry", zap.Error(err))
		}
	default:
		if err := w.finish(cleanupCtx, attempt, "platform", nil, fmt.Errorf("agent returned invalid job status %q", result.Status)); err != nil && !errors.Is(err, ErrJobLeaseLost) {
			w.logger.Error("job worker: record invalid response", zap.Error(err))
		}
	}
}

func (w *JobWorker) renewLease(ctx context.Context, attempt dbq.AgentJobAttempt, cancel context.CancelFunc) {
	ticker := time.NewTicker(w.lease / 3)
	defer ticker.Stop()
	expires := time.NewTimer(max(time.Until(attempt.LeaseExpiresAt.Time), time.Millisecond))
	defer expires.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expires.C:
			cancel()
			return
		case <-ticker.C:
			q := dbq.New(w.db.Pool())
			updated, err := q.RenewAgentJobAttemptLease(ctx, dbq.RenewAgentJobAttemptLeaseParams{
				LeaseSeconds: int32(w.lease / time.Second), JobID: attempt.JobID,
				AttemptNumber: attempt.AttemptNumber, LeaseOwner: attempt.LeaseOwner, LeaseToken: attempt.LeaseToken,
			})
			if err != nil {
				w.logger.Error("job worker: renew lease", zap.String("job", pgUUID(attempt.JobID).String()), zap.Error(err))
				continue
			}
			if updated == 0 {
				cancel()
				return
			}
			if !expires.Stop() {
				select {
				case <-expires.C:
				default:
				}
			}
			expires.Reset(w.lease)
			job, err := q.GetAgentJobByID(ctx, attempt.JobID)
			if err == nil && job.CancelRequestedAt.Valid {
				cancel()
				return
			}
		}
	}
}

func (w *JobWorker) finish(ctx context.Context, attempt dbq.AgentJobAttempt, outcome string, output []byte, outcomeErr error) error {
	tx, err := w.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	job, err := q.GetAgentJobByIDForUpdate(ctx, attempt.JobID)
	if err != nil {
		return err
	}
	if job.Status != "running" {
		return ErrJobLeaseLost
	}
	message := boundedJobError(outcomeErr)
	if job.CancelRequestedAt.Valid {
		updated, err := q.InterruptAgentJobAttempt(ctx, dbq.InterruptAgentJobAttemptParams{
			ErrorMessage: pgText("job cancelled"), JobID: attempt.JobID, AttemptNumber: attempt.AttemptNumber,
			LeaseOwner: attempt.LeaseOwner, LeaseToken: attempt.LeaseToken,
		})
		if err != nil || updated == 0 {
			return staleAttemptError(err)
		}
		if _, err := q.CancelRunningAgentJob(ctx, dbq.CancelRunningAgentJobParams{ID: job.ID, CancelledByUserID: job.CancelledByUserID}); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	switch outcome {
	case "success":
		updated, err := q.SucceedAgentJobAttempt(ctx, dbq.SucceedAgentJobAttemptParams{
			JobID: attempt.JobID, AttemptNumber: attempt.AttemptNumber, LeaseOwner: attempt.LeaseOwner, LeaseToken: attempt.LeaseToken,
		})
		if err != nil || updated == 0 {
			return staleAttemptError(err)
		}
		updated, err = q.SucceedAgentJob(ctx, dbq.SucceedAgentJobParams{OutputPayload: output, ID: job.ID})
		if err != nil || updated == 0 {
			return staleAttemptError(err)
		}
	case "agent":
		updated, err := q.FailAgentJobAttempt(ctx, dbq.FailAgentJobAttemptParams{
			ErrorKind: pgText("agent"), ErrorMessage: pgText(message), JobID: attempt.JobID,
			AttemptNumber: attempt.AttemptNumber, LeaseOwner: attempt.LeaseOwner, LeaseToken: attempt.LeaseToken,
		})
		if err != nil || updated == 0 {
			return staleAttemptError(err)
		}
		updated, err = q.FailAgentJob(ctx, dbq.FailAgentJobParams{LastError: pgText(message), ID: job.ID})
		if err != nil || updated == 0 {
			return staleAttemptError(err)
		}
	case "platform":
		if outcomeErr == nil {
			return errors.New("platform outcome requires an error")
		}
		if job.AttemptCount >= job.AttemptLimit {
			updated, err := q.FailAgentJobAttempt(ctx, dbq.FailAgentJobAttemptParams{
				ErrorKind: pgText("platform"), ErrorMessage: pgText(message), JobID: attempt.JobID,
				AttemptNumber: attempt.AttemptNumber, LeaseOwner: attempt.LeaseOwner, LeaseToken: attempt.LeaseToken,
			})
			if err != nil || updated == 0 {
				return staleAttemptError(err)
			}
			updated, err = q.FailAgentJob(ctx, dbq.FailAgentJobParams{LastError: pgText(message), ID: job.ID})
			if err != nil || updated == 0 {
				return staleAttemptError(err)
			}
		} else {
			updated, err := q.RetryAgentJobAttempt(ctx, dbq.RetryAgentJobAttemptParams{
				ErrorMessage: pgText(message), JobID: attempt.JobID, AttemptNumber: attempt.AttemptNumber,
				LeaseOwner: attempt.LeaseOwner, LeaseToken: attempt.LeaseToken,
			})
			if err != nil || updated == 0 {
				return staleAttemptError(err)
			}
			updated, err = q.RetryAgentJob(ctx, dbq.RetryAgentJobParams{
				LastError: pgText(message), BackoffSeconds: retryBackoff(job.AttemptCount), ID: job.ID,
			})
			if err != nil || updated == 0 {
				return staleAttemptError(err)
			}
		}
	case "deployment":
		if outcomeErr == nil {
			return errors.New("deployment outcome requires an error")
		}
		agent, err := q.GetAgentByID(ctx, job.AgentID)
		if err != nil {
			return err
		}
		if !agent.JobDispatchPausedBuildID.Valid {
			return errors.New("job requested a deployment retry while dispatch was not paused")
		}
		updated, err := q.RetryAgentJobAttempt(ctx, dbq.RetryAgentJobAttemptParams{
			ErrorMessage: pgText(message), JobID: attempt.JobID, AttemptNumber: attempt.AttemptNumber,
			LeaseOwner: attempt.LeaseOwner, LeaseToken: attempt.LeaseToken,
		})
		if err != nil || updated == 0 {
			return staleAttemptError(err)
		}
		updated, err = q.RetryAgentJobForDeployment(ctx, dbq.RetryAgentJobForDeploymentParams{
			LastError: pgText(message), ID: job.ID,
		})
		if err != nil || updated == 0 {
			return staleAttemptError(err)
		}
	default:
		return fmt.Errorf("unknown job outcome %q", outcome)
	}
	return tx.Commit(ctx)
}

func (w *JobWorker) recoverExpired(ctx context.Context) error {
	for {
		recovered, err := w.recoverAttempt(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !recovered {
			return nil
		}
	}
}

func (w *JobWorker) recoverAttempt(ctx context.Context) (bool, error) {
	tx, err := w.db.Pool().Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	attempt, err := q.GetExpiredAgentJobAttemptForUpdate(ctx)
	if err != nil {
		return false, err
	}
	job, err := q.GetAgentJobByID(ctx, attempt.JobID)
	if err != nil {
		return false, err
	}
	message := "job delivery lease expired"
	updated, err := q.InterruptExpiredAgentJobAttempt(ctx, dbq.InterruptExpiredAgentJobAttemptParams{
		ErrorMessage: pgText(message), JobID: attempt.JobID, AttemptNumber: attempt.AttemptNumber, LeaseToken: attempt.LeaseToken,
	})
	if err != nil || updated == 0 {
		return false, staleAttemptError(err)
	}
	if attempt.RunID.Valid {
		if _, err := q.FailRunDispatch(ctx, dbq.FailRunDispatchParams{
			ID: attempt.RunID, ErrorMessage: message,
		}); err != nil {
			return false, err
		}
	}
	if job.CancelRequestedAt.Valid {
		if _, err := q.CancelRunningAgentJob(ctx, dbq.CancelRunningAgentJobParams{ID: job.ID, CancelledByUserID: job.CancelledByUserID}); err != nil {
			return false, err
		}
	} else if job.AttemptCount >= job.AttemptLimit {
		updated, err := q.FailAgentJob(ctx, dbq.FailAgentJobParams{LastError: pgText(message), ID: job.ID})
		if err != nil || updated == 0 {
			return false, staleAttemptError(err)
		}
	} else {
		updated, err := q.RetryAgentJob(ctx, dbq.RetryAgentJobParams{LastError: pgText(message), BackoffSeconds: 0, ID: job.ID})
		if err != nil || updated == 0 {
			return false, staleAttemptError(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func retryBackoff(attempt int32) int32 {
	return int32(5 << min(attempt-1, 6))
}

func staleAttemptError(err error) error {
	if err != nil {
		return err
	}
	return ErrJobLeaseLost
}

func boundedJobError(err error) string {
	if err == nil {
		return "job failed"
	}
	message := err.Error()
	if len(message) <= maxJobErrorBytes {
		return message
	}
	message = message[:maxJobErrorBytes]
	for !utf8.ValidString(message) {
		message = message[:len(message)-1]
	}
	return message
}

func pgText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: true}
}
