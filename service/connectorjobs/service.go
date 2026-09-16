// Package connectorjobs owns durable connector command dispatch, delivery
// leases, progress, cancellation, completion, and cross-replica waiting.
package connectorjobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/db/notifications"
	"github.com/airlockrun/airlock/service"
	connectorssvc "github.com/airlockrun/airlock/service/connectors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const MaxPayloadBytes = 1 << 20

type Service struct {
	db            *db.DB
	logger        *zap.Logger
	notifications *notifications.Relay
}

type Detail struct {
	Job    dbq.ConnectorJob
	Events []dbq.ConnectorJobEvent
}

func New(database *db.DB, relay *notifications.Relay, logger *zap.Logger) *Service {
	if database == nil || relay == nil || logger == nil {
		panic("connectorjobs: nil dependency")
	}
	return &Service{db: database, notifications: relay, logger: logger}
}

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func (s *Service) Enqueue(ctx context.Context, agentID uuid.UUID, needSlug string, requestID uuid.UUID, operation, mode string, revision int32, inputSchemaHash, outputSchemaHash string, input json.RawMessage, timeout time.Duration) (dbq.ConnectorJob, error) {
	if requestID == uuid.Nil {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "connector request ID is required")
	}
	requestHash, err := hashRequest(struct {
		Operation, Mode, InputSchemaHash, OutputSchemaHash string
		Revision                                           int32
		Input                                              json.RawMessage
		Timeout                                            int64
	}{operation, mode, inputSchemaHash, outputSchemaHash, revision, input, int64(timeout)})
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	q := dbq.New(s.db.Pool())
	existing, err := q.GetConnectorJobByRequest(ctx, dbq.GetConnectorJobByRequestParams{AgentID: pg(agentID), NeedSlug: needSlug, RequestID: pg(requestID)})
	if err == nil {
		if existing.RequestHash != requestHash {
			return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "connector request ID was already used with different content")
		}
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, err
	}
	if len(input) == 0 || len(input) > MaxPayloadBytes || !json.Valid(input) {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "connector command input must be valid JSON no larger than 1 MiB")
	}
	if timeout <= 0 || timeout > 24*time.Hour {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "connector command timeout must be between 1ns and 24h")
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	defer tx.Rollback(ctx)
	q = dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(agentID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.ConnectorJob{}, service.ErrNotFound
		}
		return dbq.ConnectorJob{}, err
	}
	needParams := dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: "connector", Slug: needSlug}
	discoveredNeed, err := q.GetResourceNeed(ctx, needParams)
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.Detail(service.ErrNotFound, "connector need %q is not bound", needSlug)
	}
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if !discoveredNeed.BoundConnectorID.Valid {
		return dbq.ConnectorJob{}, service.Detail(service.ErrNotFound, "connector need %q is not bound", needSlug)
	}
	connectorID := uuid.UUID(discoveredNeed.BoundConnectorID.Bytes)
	locked, err := connectorssvc.LockResources(ctx, q, []uuid.UUID{connectorID})
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	needRow, err := q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams(needParams))
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if needRow.ID != discoveredNeed.ID || !needRow.BoundConnectorID.Valid || uuid.UUID(needRow.BoundConnectorID.Bytes) != connectorID || needRow.BoundConnectorGroupID.Valid {
		return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "connector need binding changed; retry command")
	}
	reservation, err := q.GetConnectorReservationForUpdate(ctx, pg(connectorID))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (reservation.NeedID != needRow.ID || reservation.ConnectorTargetGroupID.Valid) {
		return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "connector reservation no longer matches the need binding")
	}
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if existing, err := q.GetConnectorJobByRequest(ctx, dbq.GetConnectorJobByRequestParams{AgentID: pg(agentID), NeedSlug: needSlug, RequestID: pg(requestID)}); err == nil {
		if existing.RequestHash != requestHash {
			return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "connector request ID was already used with different content")
		}
		return existing, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, err
	}
	bound := locked[connectorID]
	if bound.Lifecycle != "active" || bound.Readiness != "ready" {
		return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "bound connector is not ready")
	}
	need, err := connectorssvc.ParseNeedSpec(needRow.Spec)
	if err != nil {
		return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "%v", err)
	}
	descriptor, err := connectorssvc.ParseDescriptor(bound.InterfaceDescriptor)
	if err != nil {
		return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "bound connector has not published a valid interface")
	}
	if err := connectorssvc.Compatible(need, descriptor); err != nil {
		return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "%v", err)
	}
	command, err := connectorssvc.RequiredCommand(need, operation, mode)
	if err != nil {
		return dbq.ConnectorJob{}, service.Detail(service.ErrForbidden, "%v", err)
	}
	if command.Revision != revision || command.InputSchemaHash != inputSchemaHash || command.OutputSchemaHash != outputSchemaHash {
		return dbq.ConnectorJob{}, service.Detail(service.ErrForbidden, "connector command contract does not exactly match the declared need")
	}
	jobID := uuid.NewSHA1(requestID, []byte(agentID.String()+":"+uuid.UUID(needRow.ID.Bytes).String()+":job"))
	idempotencyKey := uuid.NewSHA1(requestID, []byte("connector-execution"))
	row, err := q.InsertConnectorJob(ctx, dbq.InsertConnectorJobParams{
		ID: pg(jobID), ConnectorID: bound.ID, AgentID: pg(agentID), NeedID: needRow.ID, RequestID: pg(requestID), CanaryCohort: false,
		OperationKind: "command", OperationName: operation, OperationRevision: command.Revision, Mode: mode,
		InputSchemaHash: command.InputSchemaHash, OutputSchemaHash: command.OutputSchemaHash,
		InputPayload: input, RequestHash: requestHash, Status: "queued", IdempotencyKey: pg(idempotencyKey),
		DeadlineAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(timeout), Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "connector request ID was already used with different content")
	}
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.ConnectorJob{}, err
	}
	return dbq.ConnectorJob(row), nil
}

func hashRequest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Service) AppendEvent(ctx context.Context, connectorID, jobID, attemptToken uuid.UUID, attemptSequence int64, kind string, payload json.RawMessage) (dbq.AppendConnectorJobEventRow, error) {
	if attemptSequence <= 0 {
		return dbq.AppendConnectorJobEventRow{}, service.Detail(service.ErrInvalidInput, "connector event sequence must be positive")
	}
	if len(payload) == 0 || len(payload) > 64<<10 || !json.Valid(payload) {
		return dbq.AppendConnectorJobEventRow{}, service.Detail(service.ErrInvalidInput, "connector event must be valid JSON no larger than 64 KiB")
	}
	if kind != "progress" && kind != "log" && kind != "status" {
		return dbq.AppendConnectorJobEventRow{}, service.Detail(service.ErrInvalidInput, "invalid connector event kind")
	}
	row, err := dbq.New(s.db.Pool()).AppendConnectorJobEvent(ctx, dbq.AppendConnectorJobEventParams{
		ConnectorID: pg(connectorID), JobID: pg(jobID), AttemptToken: pg(attemptToken), AttemptSequence: attemptSequence, Kind: kind, Payload: payload,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.AppendConnectorJobEventRow{}, service.Detail(service.ErrConflict, "connector job lease is stale")
	}
	if err == nil {
		stored, storedErr := protocol.CanonicalJSON(row.Payload)
		received, receivedErr := protocol.CanonicalJSON(payload)
		if row.Kind != kind || storedErr != nil || receivedErr != nil || !bytes.Equal(stored, received) {
			return dbq.AppendConnectorJobEventRow{}, service.Detail(service.ErrConflict, "connector event sequence was already used with different content")
		}
	}
	return row, err
}

func (s *Service) Complete(ctx context.Context, connectorID, jobID, attemptToken uuid.UUID, succeeded bool, output json.RawMessage, errorCode, errorMessage string) (dbq.ConnectorJob, error) {
	if len(output) > MaxPayloadBytes || len(output) > 0 && !json.Valid(output) {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "connector output must be valid JSON no larger than 1 MiB")
	}
	if succeeded && (len(output) == 0 || len(output) > MaxPayloadBytes || !json.Valid(output)) {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "connector command output must be valid JSON no larger than 1 MiB")
	}
	if len(errorCode) > 128 || len(errorMessage) > 4096 {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "connector error exceeds its size limit")
	}
	row, err := dbq.New(s.db.Pool()).CompleteConnectorJob(ctx, dbq.CompleteConnectorJobParams{
		ConnectorID: pg(connectorID), JobID: pg(jobID), AttemptToken: pg(attemptToken), Succeeded: succeeded,
		OutputPayload: output, ErrorCode: errorCode, ErrorMessage: errorMessage,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		row, err = dbq.New(s.db.Pool()).ReplayConnectorCompletion(ctx, dbq.ReplayConnectorCompletionParams{
			ConnectorID: pg(connectorID), JobID: pg(jobID), AttemptToken: pg(attemptToken), Succeeded: succeeded,
			OutputPayload: output, ErrorCode: errorCode, ErrorMessage: errorMessage,
		})
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "connector job lease is stale")
	}
	return row, err
}

func (s *Service) Get(ctx context.Context, agentID, jobID uuid.UUID) (dbq.ConnectorJob, error) {
	q := dbq.New(s.db.Pool())
	if _, err := q.FailExpiredConnectorJobs(ctx, 100); err != nil {
		return dbq.ConnectorJob{}, err
	}
	row, err := q.GetConnectorJobByAgent(ctx, dbq.GetConnectorJobByAgentParams{ID: pg(jobID), AgentID: pg(agentID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.ErrNotFound
	}
	return row, err
}

func (s *Service) GetForNeed(ctx context.Context, agentID, jobID uuid.UUID, needSlug string) (dbq.ConnectorJob, error) {
	q := dbq.New(s.db.Pool())
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: "connector", Slug: needSlug})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	job, err := s.Get(ctx, agentID, jobID)
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if job.NeedID != need.ID {
		return dbq.ConnectorJob{}, service.ErrNotFound
	}
	return job, nil
}

func (s *Service) DetailForNeed(ctx context.Context, agentID, jobID uuid.UUID, needSlug string) (Detail, error) {
	job, err := s.GetForNeed(ctx, agentID, jobID, needSlug)
	if err != nil {
		return Detail{}, err
	}
	events, err := dbq.New(s.db.Pool()).ListConnectorJobEvents(ctx, dbq.ListConnectorJobEventsParams{JobID: job.ID, AfterSequence: 0, Lim: 1000})
	return Detail{Job: job, Events: events}, err
}

func (s *Service) Cancel(ctx context.Context, agentID, jobID uuid.UUID) (dbq.ConnectorJob, error) {
	row, err := dbq.New(s.db.Pool()).CancelConnectorJob(ctx, dbq.CancelConnectorJobParams{ID: pg(jobID), AgentID: pg(agentID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.ErrNotFound
	}
	return dbq.ConnectorJob(row), err
}

func (s *Service) CancelForNeed(ctx context.Context, agentID, jobID uuid.UUID, needSlug string) (dbq.ConnectorJob, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	need, err := q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams{AgentID: pg(agentID), Type: "connector", Slug: needSlug})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	job, err := q.GetConnectorJobByAgentForUpdate(ctx, dbq.GetConnectorJobByAgentForUpdateParams{ID: pg(jobID), AgentID: pg(agentID)})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && job.NeedID != need.ID {
		return dbq.ConnectorJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	cancelled, err := q.CancelConnectorJob(ctx, dbq.CancelConnectorJobParams{ID: pg(jobID), AgentID: pg(agentID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.ConnectorJob{}, err
	}
	return dbq.ConnectorJob(cancelled), nil
}

func (s *Service) Wait(ctx context.Context, agentID, jobID uuid.UUID) (dbq.ConnectorJob, error) {
	sub := s.notifications.Subscribe(notifications.ConnectorEvents, jobID)
	defer sub.Close()
	terminal := func() (dbq.ConnectorJob, bool, error) {
		job, err := s.Get(ctx, agentID, jobID)
		if err != nil {
			return dbq.ConnectorJob{}, false, err
		}
		switch job.Status {
		case "succeeded", "failed", "cancelled", "skipped":
			return job, true, nil
		default:
			return job, false, nil
		}
	}
	for {
		job, done, err := terminal()
		if err != nil || done {
			return job, err
		}
		waitCtx, cancel := context.WithDeadline(ctx, job.DeadlineAt.Time)
		err = sub.Wait(waitCtx)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			job, done, terminalErr := terminal()
			if terminalErr != nil {
				return dbq.ConnectorJob{}, terminalErr
			}
			if done {
				return job, nil
			}
			return dbq.ConnectorJob{}, errors.New("connector job remained nonterminal after its deadline")
		}
		if err != nil {
			return dbq.ConnectorJob{}, err
		}
	}
}
