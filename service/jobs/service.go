// Package jobs owns durable background-job acceptance and lifecycle access.
package jobs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const (
	MaxInputBytes        = 64 * 1024
	DefaultListLimit     = 50
	MaxListLimit         = 100
	maxProgressPhase     = 128
	maxProgressMessage   = 4096
	manualRetryHardLimit = 100
)

var ErrCandidateContractIncompatible = errors.New("job contract is incompatible with the candidate deployment")

// CandidateContractError identifies work that cannot run on the deployment
// currently holding the agent's dispatch pause.
type CandidateContractError struct {
	HandlerName      string
	HandlerVersion   int32
	InputSchemaHash  string
	OutputSchemaHash string
}

func (e *CandidateContractError) Error() string {
	return fmt.Sprintf("%s: %s@v%d", ErrCandidateContractIncompatible, e.HandlerName, e.HandlerVersion)
}

func (e *CandidateContractError) Is(target error) bool {
	return target == ErrCandidateContractIncompatible || target == service.ErrConflict
}

type Service struct {
	db     *db.DB
	wake   func()
	logger *zap.Logger
}

func New(database *db.DB, wake func(), logger *zap.Logger) *Service {
	if database == nil {
		panic("jobs: db is required")
	}
	if logger == nil {
		panic("jobs: logger is required")
	}
	if wake == nil {
		panic("jobs: wake is required")
	}
	return &Service{db: database, wake: wake, logger: logger}
}

// Wake notifies the local worker after another service commits accepted work.
func (s *Service) Wake() {
	s.wake()
}

type EnqueueRequest struct {
	ID                uuid.UUID
	AgentID           uuid.UUID
	RuntimeGeneration int64
	SourceRunID       uuid.UUID
	HandlerName       string
	HandlerVersion    int32
	InputSchemaHash   string
	OutputSchemaHash  string
	Input             []byte
	ScheduledAt       *time.Time
}

type EnqueueResult struct {
	Job     dbq.AgentJob
	Created bool
}

func (s *Service) Enqueue(ctx context.Context, request EnqueueRequest) (EnqueueResult, error) {
	if request.ID == uuid.Nil || request.AgentID == uuid.Nil || request.SourceRunID == uuid.Nil {
		return EnqueueResult{}, service.Detail(service.ErrInvalidInput, "job, agent, and source run IDs are required")
	}
	if request.RuntimeGeneration <= 0 || request.HandlerName == "" || request.HandlerVersion <= 0 || len(request.InputSchemaHash) != 64 || len(request.OutputSchemaHash) != 64 {
		return EnqueueResult{}, service.Detail(service.ErrInvalidInput, "invalid job contract")
	}
	input, err := canonicalInput(request.Input)
	if err != nil {
		return EnqueueResult{}, service.Detail(service.ErrInvalidInput, "invalid job input: %v", err)
	}
	var scheduledAt pgtype.Timestamptz
	if request.ScheduledAt != nil {
		if request.ScheduledAt.IsZero() {
			return EnqueueResult{}, service.Detail(service.ErrInvalidInput, "scheduled time is required")
		}
		normalized := request.ScheduledAt.UTC().Truncate(time.Microsecond)
		request.ScheduledAt = &normalized
		scheduledAt = pgtype.Timestamptz{Time: normalized, Valid: true}
	}

	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return EnqueueResult{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	pgAgentID := toPgUUID(request.AgentID)
	agent, err := q.GetAgentByIDForUpdate(ctx, pgAgentID)
	if err != nil {
		return EnqueueResult{}, service.ErrNotFound
	}

	lookup := dbq.GetAgentJobByIDAndAgentParams{ID: toPgUUID(request.ID), AgentID: pgAgentID}
	existing, err := q.GetAgentJobByIDAndAgent(ctx, lookup)
	if err == nil {
		if !sameAcceptedJob(existing, request, input) {
			return EnqueueResult{}, service.Detail(service.ErrConflict, "job ID is already bound to different work")
		}
		if err := tx.Commit(ctx); err != nil {
			return EnqueueResult{}, err
		}
		return EnqueueResult{Job: existing}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return EnqueueResult{}, err
	}
	if agent.AgentTokenVersion != request.RuntimeGeneration || (agent.Status != "active" && agent.Status != "building") {
		return EnqueueResult{}, service.Detail(service.ErrConflict, "agent runtime generation is no longer active")
	}
	if agent.JobDispatchPausedBuildID.Valid {
		compatible, err := q.CandidateAgentJobContractMatches(ctx, dbq.CandidateAgentJobContractMatchesParams{
			BuildID:          agent.JobDispatchPausedBuildID,
			AgentID:          pgAgentID,
			HandlerName:      request.HandlerName,
			HandlerVersion:   request.HandlerVersion,
			InputSchemaHash:  request.InputSchemaHash,
			OutputSchemaHash: request.OutputSchemaHash,
		})
		if err != nil {
			return EnqueueResult{}, err
		}
		if !compatible {
			return EnqueueResult{}, candidateContractError(request.HandlerName, request.HandlerVersion, request.InputSchemaHash, request.OutputSchemaHash)
		}
	}

	source, err := q.GetRunningRunForJobEnqueue(ctx, dbq.GetRunningRunForJobEnqueueParams{
		SourceRunID: toPgUUID(request.SourceRunID), AgentID: pgAgentID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EnqueueResult{}, service.Detail(service.ErrConflict, "source run is not active for this agent")
		}
		return EnqueueResult{}, err
	}
	handler, err := q.GetAgentJobHandlerForEnqueue(ctx, dbq.GetAgentJobHandlerForEnqueueParams{
		AgentID: pgAgentID, HandlerName: request.HandlerName, HandlerVersion: request.HandlerVersion,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EnqueueResult{}, service.Detail(service.ErrConflict, "job handler is not active in this runtime generation")
		}
		return EnqueueResult{}, err
	}
	if handler.InputSchemaHash != request.InputSchemaHash || handler.OutputSchemaHash != request.OutputSchemaHash {
		return EnqueueResult{}, service.Detail(service.ErrConflict, "job handler schema does not match the active contract")
	}

	kind, userID, conversationID, access, err := initiatorFromRun(ctx, q, source)
	if err != nil {
		return EnqueueResult{}, service.Detail(service.ErrConflict, "source run has no trusted job provenance: %v", err)
	}
	job, err := q.InsertAgentJob(ctx, dbq.InsertAgentJobParams{
		ID:                      toPgUUID(request.ID),
		AgentID:                 pgAgentID,
		HandlerName:             handler.Name,
		HandlerVersion:          handler.Version,
		InputSchemaHash:         handler.InputSchemaHash,
		OutputSchemaHash:        handler.OutputSchemaHash,
		SourceRunID:             source.ID,
		InitiatorKind:           kind,
		InitiatorUserID:         userID,
		InitiatorConversationID: conversationID,
		InitiatorAccess:         access,
		TimeoutMs:               handler.TimeoutMs,
		MaxAttempts:             handler.MaxAttempts,
		ScheduledAt:             scheduledAt,
		InputPayload:            input,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EnqueueResult{}, service.Detail(service.ErrConflict, "job ID is already in use")
		}
		return EnqueueResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return EnqueueResult{}, err
	}
	s.wake()
	return EnqueueResult{Job: job, Created: true}, nil
}

type GetResult struct {
	Job      dbq.AgentJob
	Attempts []dbq.AgentJobAttempt
}

type ListOptions struct {
	Limit  int32
	Cursor string
}

type ListPage struct {
	Jobs       []dbq.AgentJob
	NextCursor string
}

type listCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func ParseListOptions(limitValues, cursorValues []string) (ListOptions, error) {
	options := ListOptions{Limit: DefaultListLimit}
	if len(limitValues) > 1 || len(cursorValues) > 1 {
		return ListOptions{}, service.Detail(service.ErrInvalidInput, "limit and cursor may be specified once")
	}
	if len(limitValues) == 1 {
		limit, err := strconv.Atoi(limitValues[0])
		if err != nil || limit <= 0 || limit > MaxListLimit {
			return ListOptions{}, service.Detail(service.ErrInvalidInput, "limit must be between 1 and %d", MaxListLimit)
		}
		options.Limit = int32(limit)
	}
	if len(cursorValues) == 1 {
		if cursorValues[0] == "" {
			return ListOptions{}, service.Detail(service.ErrInvalidInput, "cursor is invalid")
		}
		options.Cursor = cursorValues[0]
	}
	return options, nil
}

func (s *Service) GetForAgent(ctx context.Context, agentID, jobID uuid.UUID) (GetResult, error) {
	tx, err := s.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return GetResult{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	job, err := q.GetAgentJobByIDAndAgent(ctx, dbq.GetAgentJobByIDAndAgentParams{ID: toPgUUID(jobID), AgentID: toPgUUID(agentID)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return GetResult{}, service.ErrNotFound
		}
		return GetResult{}, err
	}
	attempts, err := q.ListAgentJobAttempts(ctx, job.ID)
	if err != nil {
		return GetResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return GetResult{}, err
	}
	return GetResult{Job: job, Attempts: attempts}, nil
}

func (s *Service) ListForAgent(ctx context.Context, agentID uuid.UUID, options ListOptions) (ListPage, error) {
	return s.list(ctx, dbq.New(s.db.Pool()), agentID, options)
}

func (s *Service) CancelForAgent(ctx context.Context, agentID, jobID uuid.UUID) (dbq.AgentJob, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.AgentJob{}, err
	}
	defer tx.Rollback(ctx)
	job, err := cancelJob(ctx, dbq.New(tx), agentID, jobID, pgtype.UUID{})
	if err != nil {
		return dbq.AgentJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.AgentJob{}, err
	}
	s.wake()
	return job, nil
}

func (s *Service) List(ctx context.Context, principal authz.Principal, agentID uuid.UUID, options ListOptions) (ListPage, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, principal, authz.AgentJobView, agentID); err != nil {
		return ListPage{}, err
	}
	return s.list(ctx, q, agentID, options)
}

// ListBuildBlockers returns incompatible nonterminal jobs for one candidate
// build. The build-agent relationship is checked before authorization.
func (s *Service) ListBuildBlockers(ctx context.Context, principal authz.Principal, agentID, buildID uuid.UUID, options ListOptions) (ListPage, error) {
	if agentID == uuid.Nil || buildID == uuid.Nil || options.Limit <= 0 || options.Limit > MaxListLimit {
		return ListPage{}, service.Detail(service.ErrInvalidInput, "invalid build blocker list options")
	}
	q := dbq.New(s.db.Pool())
	build, err := q.GetAgentBuild(ctx, toPgUUID(buildID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ListPage{}, service.ErrNotFound
	}
	if err != nil {
		return ListPage{}, err
	}
	if uuid.UUID(build.AgentID.Bytes) != agentID {
		return ListPage{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, principal, authz.AgentJobView, agentID); err != nil {
		return ListPage{}, err
	}

	var cursorCreatedAt pgtype.Timestamptz
	var cursorID pgtype.UUID
	if options.Cursor != "" {
		cursor, err := decodeListCursor(options.Cursor)
		if err != nil {
			return ListPage{}, service.Detail(service.ErrInvalidInput, "cursor is invalid")
		}
		id, _ := uuid.Parse(cursor.ID)
		cursorCreatedAt = pgtype.Timestamptz{Time: cursor.CreatedAt, Valid: true}
		cursorID = toPgUUID(id)
	}
	listed, err := q.ListAgentBuildBlockingJobs(ctx, dbq.ListAgentBuildBlockingJobsParams{
		BuildID: toPgUUID(buildID), AgentID: toPgUUID(agentID),
		CursorCreatedAt: cursorCreatedAt, CursorID: cursorID, Lim: options.Limit + 1,
	})
	if err != nil {
		return ListPage{}, err
	}
	page := ListPage{Jobs: listed}
	if len(listed) > int(options.Limit) {
		page.Jobs = listed[:options.Limit]
		page.NextCursor, err = encodeListCursor(page.Jobs[len(page.Jobs)-1])
		if err != nil {
			return ListPage{}, err
		}
	}
	return page, nil
}

func (s *Service) list(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, options ListOptions) (ListPage, error) {
	if agentID == uuid.Nil || options.Limit <= 0 || options.Limit > MaxListLimit {
		return ListPage{}, service.Detail(service.ErrInvalidInput, "invalid job list options")
	}
	var cursorCreatedAt pgtype.Timestamptz
	var cursorID pgtype.UUID
	if options.Cursor != "" {
		cursor, err := decodeListCursor(options.Cursor)
		if err != nil {
			return ListPage{}, service.Detail(service.ErrInvalidInput, "cursor is invalid")
		}
		id, _ := uuid.Parse(cursor.ID)
		cursorCreatedAt = pgtype.Timestamptz{Time: cursor.CreatedAt, Valid: true}
		cursorID = toPgUUID(id)
	}
	jobs, err := q.ListAgentJobsByAgent(ctx, dbq.ListAgentJobsByAgentParams{
		AgentID: toPgUUID(agentID), CursorCreatedAt: cursorCreatedAt, CursorID: cursorID, Lim: options.Limit + 1,
	})
	if err != nil {
		return ListPage{}, err
	}
	page := ListPage{Jobs: jobs}
	if len(jobs) > int(options.Limit) {
		page.Jobs = jobs[:options.Limit]
		last := page.Jobs[len(page.Jobs)-1]
		page.NextCursor, err = encodeListCursor(last)
		if err != nil {
			return ListPage{}, err
		}
	}
	return page, nil
}

func decodeListCursor(encoded string) (listCursor, error) {
	if len(encoded) > 1024 {
		return listCursor{}, errors.New("cursor is too long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return listCursor{}, errors.New("cursor is not base64url")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cursor listCursor
	if err := decoder.Decode(&cursor); err != nil {
		return listCursor{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return listCursor{}, errors.New("cursor contains trailing data")
	}
	id, err := uuid.Parse(cursor.ID)
	if err != nil || id == uuid.Nil || id.String() != cursor.ID || cursor.CreatedAt.IsZero() {
		return listCursor{}, errors.New("cursor tuple is invalid")
	}
	return cursor, nil
}

func encodeListCursor(job dbq.AgentJob) (string, error) {
	raw, err := json.Marshal(listCursor{CreatedAt: job.CreatedAt.Time, ID: uuid.UUID(job.ID.Bytes).String()})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *Service) ListHandlers(ctx context.Context, principal authz.Principal, agentID uuid.UUID) ([]dbq.AgentJobHandler, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, principal, authz.AgentJobView, agentID); err != nil {
		return nil, err
	}
	return q.ListJobHandlersByAgent(ctx, toPgUUID(agentID))
}

func (s *Service) Get(ctx context.Context, principal authz.Principal, jobID uuid.UUID) (GetResult, error) {
	tx, err := s.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return GetResult{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	job, err := q.GetAgentJobByID(ctx, toPgUUID(jobID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return GetResult{}, service.ErrNotFound
		}
		return GetResult{}, err
	}
	if err := authz.Authorize(ctx, q, principal, authz.AgentJobView, uuid.UUID(job.AgentID.Bytes)); err != nil {
		return GetResult{}, err
	}
	attempts, err := q.ListAgentJobAttempts(ctx, job.ID)
	if err != nil {
		return GetResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return GetResult{}, err
	}
	return GetResult{Job: job, Attempts: attempts}, nil
}

type ProgressRequest struct {
	JobID             uuid.UUID
	AgentID           uuid.UUID
	RuntimeGeneration int64
	RunID             uuid.UUID
	LeaseToken        uuid.UUID
	Attempt           int32
	Phase             string
	Message           string
	Completed         int64
	Total             int64
}

func (s *Service) UpdateProgress(ctx context.Context, request ProgressRequest) error {
	if request.JobID == uuid.Nil || request.AgentID == uuid.Nil || request.RunID == uuid.Nil || request.LeaseToken == uuid.Nil || request.RuntimeGeneration <= 0 {
		return service.Detail(service.ErrInvalidInput, "job progress fence is invalid")
	}
	if request.Attempt <= 0 {
		return service.Detail(service.ErrInvalidInput, "attempt must be positive")
	}
	if strings.TrimSpace(request.Phase) == "" || len(request.Phase) > maxProgressPhase {
		return service.Detail(service.ErrInvalidInput, "phase must be nonblank and at most %d bytes", maxProgressPhase)
	}
	if len(request.Message) > maxProgressMessage {
		return service.Detail(service.ErrInvalidInput, "message must be at most %d bytes", maxProgressMessage)
	}
	if request.Completed < 0 || request.Total < 0 || (request.Total == 0 && request.Completed != 0) || (request.Total > 0 && request.Completed > request.Total) {
		return service.Detail(service.ErrInvalidInput, "progress counts are invalid")
	}
	_, err := dbq.New(s.db.Pool()).UpdateAgentJobProgress(ctx, dbq.UpdateAgentJobProgressParams{
		ProgressPhase: pgtype.Text{String: request.Phase, Valid: true}, ProgressMessage: pgtype.Text{String: request.Message, Valid: true},
		ProgressCompleted: pgtype.Int8{Int64: request.Completed, Valid: true}, ProgressTotal: pgtype.Int8{Int64: request.Total, Valid: true},
		AttemptNumber: pgtype.Int4{Int32: request.Attempt, Valid: true}, JobID: toPgUUID(request.JobID), AgentID: toPgUUID(request.AgentID),
		RuntimeGeneration: request.RuntimeGeneration, RunID: toPgUUID(request.RunID), LeaseToken: toPgUUID(request.LeaseToken),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return service.Detail(service.ErrConflict, "job progress fence is stale")
	}
	return err
}

func (s *Service) Retry(ctx context.Context, principal authz.Principal, jobID uuid.UUID) (dbq.AgentJob, error) {
	lookup, err := dbq.New(s.db.Pool()).GetAgentJobByID(ctx, toPgUUID(jobID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.AgentJob{}, service.ErrNotFound
		}
		return dbq.AgentJob{}, err
	}
	agentID := uuid.UUID(lookup.AgentID.Bytes)
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.AgentJob{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agent, err := q.GetAgentByIDForUpdate(ctx, lookup.AgentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.AgentJob{}, service.ErrNotFound
		}
		return dbq.AgentJob{}, err
	}
	if err := authz.Authorize(ctx, q, principal, authz.AgentJobRetry, agentID); err != nil {
		return dbq.AgentJob{}, err
	}
	job, err := q.GetAgentJobByIDAndAgentForUpdate(ctx, dbq.GetAgentJobByIDAndAgentForUpdateParams{ID: toPgUUID(jobID), AgentID: lookup.AgentID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.AgentJob{}, service.ErrNotFound
		}
		return dbq.AgentJob{}, err
	}
	if job.Status != "failed" && job.Status != "cancelled" {
		return dbq.AgentJob{}, service.Detail(service.ErrConflict, "only failed or cancelled jobs can be retried")
	}
	if job.AttemptCount >= manualRetryHardLimit {
		return dbq.AgentJob{}, service.Detail(service.ErrConflict, "job has reached the retry limit")
	}
	if agent.JobDispatchPausedBuildID.Valid {
		compatible, err := q.CandidateAgentJobContractMatches(ctx, dbq.CandidateAgentJobContractMatchesParams{
			BuildID:          agent.JobDispatchPausedBuildID,
			AgentID:          job.AgentID,
			HandlerName:      job.HandlerName,
			HandlerVersion:   job.HandlerVersion,
			InputSchemaHash:  job.InputSchemaHash,
			OutputSchemaHash: job.OutputSchemaHash,
		})
		if err != nil {
			return dbq.AgentJob{}, err
		}
		if !compatible {
			return dbq.AgentJob{}, candidateContractError(job.HandlerName, job.HandlerVersion, job.InputSchemaHash, job.OutputSchemaHash)
		}
	}
	if _, err := q.GetAgentJobHandlerForEnqueue(ctx, dbq.GetAgentJobHandlerForEnqueueParams{
		AgentID: job.AgentID, HandlerName: job.HandlerName, HandlerVersion: job.HandlerVersion,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.AgentJob{}, service.Detail(service.ErrConflict, "job handler is not active in the current runtime generation")
		}
		return dbq.AgentJob{}, err
	}
	active, err := q.HasActiveAgentJobAttempt(ctx, job.ID)
	if err != nil {
		return dbq.AgentJob{}, err
	}
	if active {
		return dbq.AgentJob{}, service.Detail(service.ErrConflict, "job still has an active attempt")
	}
	job, err = q.RetryTerminalAgentJob(ctx, job.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.AgentJob{}, service.ErrConflict
	}
	if err != nil {
		return dbq.AgentJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.AgentJob{}, err
	}
	s.wake()
	return job, nil
}

func (s *Service) Cancel(ctx context.Context, principal authz.Principal, jobID uuid.UUID) (dbq.AgentJob, error) {
	q := dbq.New(s.db.Pool())
	job, err := q.GetAgentJobByID(ctx, toPgUUID(jobID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.AgentJob{}, service.ErrNotFound
		}
		return dbq.AgentJob{}, err
	}
	agentID := uuid.UUID(job.AgentID.Bytes)
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.AgentJob{}, err
	}
	defer tx.Rollback(ctx)
	q = dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, toPgUUID(agentID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.AgentJob{}, service.ErrNotFound
		}
		return dbq.AgentJob{}, err
	}
	if err := authz.Authorize(ctx, q, principal, authz.AgentJobCancel, agentID); err != nil {
		return dbq.AgentJob{}, err
	}
	job, err = cancelJob(ctx, q, agentID, jobID, toPgUUID(principal.UserID))
	if err != nil {
		return dbq.AgentJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.AgentJob{}, err
	}
	s.wake()
	return job, nil
}

func cancelJob(ctx context.Context, q *dbq.Queries, agentID, jobID uuid.UUID, cancelledBy pgtype.UUID) (dbq.AgentJob, error) {
	params := dbq.GetAgentJobByIDAndAgentForUpdateParams{ID: toPgUUID(jobID), AgentID: toPgUUID(agentID)}
	job, err := q.GetAgentJobByIDAndAgentForUpdate(ctx, params)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.AgentJob{}, service.ErrNotFound
		}
		return dbq.AgentJob{}, err
	}
	switch job.Status {
	case "queued":
		job, err = q.CancelQueuedAgentJob(ctx, dbq.CancelQueuedAgentJobParams{CancelledByUserID: cancelledBy, ID: job.ID, AgentID: job.AgentID})
	case "running":
		active, err := q.HasActiveAgentJobAttempt(ctx, job.ID)
		if err != nil {
			return dbq.AgentJob{}, err
		}
		if !active {
			return q.CancelRunningAgentJob(ctx, dbq.CancelRunningAgentJobParams{
				ID: job.ID, CancelledByUserID: cancelledBy,
			})
		}
		if job.CancelRequestedAt.Valid {
			break
		}
		job, err = q.RequestRunningAgentJobCancellation(ctx, dbq.RequestRunningAgentJobCancellationParams{CancelledByUserID: cancelledBy, ID: job.ID, AgentID: job.AgentID})
	case "cancelled":
		// Idempotent cancellation returns the terminal row.
	case "succeeded", "failed":
		return dbq.AgentJob{}, service.ErrConflict
	default:
		return dbq.AgentJob{}, fmt.Errorf("jobs: invalid persisted status %q", job.Status)
	}
	if err != nil {
		return dbq.AgentJob{}, err
	}
	return job, nil
}

func canonicalInput(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxInputBytes {
		return nil, fmt.Errorf("input must be between 1 and %d bytes", MaxInputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, errors.New("input must be a JSON object")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("input contains trailing data")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxInputBytes {
		return nil, fmt.Errorf("canonical input exceeds %d bytes", MaxInputBytes)
	}
	return encoded, nil
}

func sameAcceptedJob(job dbq.AgentJob, request EnqueueRequest, input []byte) bool {
	if job.HandlerName != request.HandlerName || job.HandlerVersion != request.HandlerVersion ||
		job.InputSchemaHash != request.InputSchemaHash || job.OutputSchemaHash != request.OutputSchemaHash ||
		!job.SourceRunID.Valid || uuid.UUID(job.SourceRunID.Bytes) != request.SourceRunID {
		return false
	}
	if job.ScheduledAt.Valid != (request.ScheduledAt != nil) ||
		(job.ScheduledAt.Valid && !job.ScheduledAt.Time.Equal(*request.ScheduledAt)) {
		return false
	}
	existing, err := canonicalInput(job.InputPayload)
	if err != nil {
		return false
	}
	return bytes.Equal(existing, input)
}

func candidateContractError(name string, version int32, inputHash, outputHash string) error {
	return &CandidateContractError{
		HandlerName: name, HandlerVersion: version,
		InputSchemaHash: inputHash, OutputSchemaHash: outputHash,
	}
}

func initiatorFromRun(ctx context.Context, q *dbq.Queries, run dbq.Run) (string, pgtype.UUID, pgtype.UUID, string, error) {
	if run.TriggerType == "code" {
		return "", pgtype.UUID{}, pgtype.UUID{}, "", errors.New("agent-created code runs cannot authorize jobs")
	}
	if run.TriggerType == "job" {
		parent, err := q.GetAgentJobByAttemptRunID(ctx, run.ID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", pgtype.UUID{}, pgtype.UUID{}, "", errors.New("job source run has no durable parent")
			}
			return "", pgtype.UUID{}, pgtype.UUID{}, "", err
		}
		return parent.InitiatorKind, parent.InitiatorUserID, parent.InitiatorConversationID, parent.InitiatorAccess, nil
	}
	if run.TriggerType == "background" && (run.CallerUserID.Valid || run.CallerAccess != "public") {
		return "", pgtype.UUID{}, pgtype.UUID{}, "", errors.New("background runs must use system identity")
	}
	if run.CallerUserID.Valid {
		if run.CallerAccess != "user" && run.CallerAccess != "admin" {
			return "", pgtype.UUID{}, pgtype.UUID{}, "", errors.New("registered users require user or admin access")
		}
		return "user", run.CallerUserID, run.CallerConversationID, run.CallerAccess, nil
	}
	switch run.TriggerType {
	case "prompt", "route":
		return "anonymous", pgtype.UUID{}, run.CallerConversationID, "public", nil
	default:
		return "system", pgtype.UUID{}, run.CallerConversationID, "public", nil
	}
}

func toPgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil}
}
