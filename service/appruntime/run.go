package appruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/execution"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/airlock/service/systemchat"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (h *Service) CreateRun(ctx context.Context, req wire.CreateRunRequest) (wire.CreateRunResponse, error) {
	if req.TriggerType != "code" && req.TriggerType != "background" {
		return wire.CreateRunResponse{}, apperr.Detail(apperr.ErrInvalidInput, "invalid triggerType")
	}
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return wire.CreateRunResponse{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	appID, err := h.admit(ctx, q)
	if err != nil {
		return wire.CreateRunResponse{}, err
	}
	if err := execution.RequireRuntimeProtocol(ctx, q, appID); err != nil {
		return wire.CreateRunResponse{}, err
	}
	app, err := q.GetAgentByID(ctx, toPgUUID(appID))
	if err != nil {
		return wire.CreateRunResponse{}, err
	}
	origin, err := execution.AppOrigin(ctx, q, appID, auth.AgentTokenVersionFromContext(ctx), "app")
	if err != nil {
		return wire.CreateRunResponse{}, err
	}
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID: app.ID, InputPayload: []byte("{}"), SourceRef: app.SourceRef,
		OriginID: origin.ID, ExecutionKind: string(execution.App),
		TriggerType: req.TriggerType, TriggerRef: req.TriggerRef, CallerAccess: "public",
	})
	if err != nil {
		return wire.CreateRunResponse{}, err
	}
	invocation, err := execution.IssueInvocation(ctx, q, appID, pgUUID(run.ID), uuid.Nil, time.Now().Add(10*time.Minute))
	if err != nil {
		return wire.CreateRunResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return wire.CreateRunResponse{}, err
	}
	return wire.CreateRunResponse{RunID: pgUUID(run.ID).String(), InvocationToken: invocation.InvocationToken, Caller: invocation.Caller}, nil
}

func (h *Service) RunComplete(ctx context.Context, req wire.RunCompleteRequest) error {
	switch req.Status {
	case "success", "error", "timeout", "cancelled", "tool_errors":
	default:
		return apperr.Detail(apperr.ErrInvalidInput, "invalid completion status")
	}
	if len(req.Checkpoint) != 0 {
		return apperr.Detail(apperr.ErrInvalidInput, "app completion cannot write hosted checkpoints")
	}
	runID, err := parseUUID(req.RunID)
	if err != nil {
		return apperr.ErrInvalidInput
	}
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	appID, err := h.admit(ctx, q)
	if err != nil {
		return err
	}
	run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: toPgUUID(runID), AgentID: toPgUUID(appID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.ErrNotFound
	}
	if err != nil {
		return err
	}
	origin, err := q.GetRunOrigin(ctx, run.ID)
	if err != nil {
		return apperr.ErrConflict
	}
	if origin.Actor == "unknown" || origin.AgentID != run.AgentID {
		return apperr.ErrConflict
	}
	if run.ExecutionKind == "job" || run.TriggerType == "job" {
		job, err := q.GetAgentJobByAttemptRunID(ctx, run.ID)
		if err != nil {
			return apperr.ErrConflict
		}
		job, err = q.GetAgentJobByIDForUpdate(ctx, job.ID)
		if err != nil {
			return err
		}
		if job.Status != "running" || job.CancelRequestedAt.Valid || req.JobID != pgUUID(job.ID).String() {
			return apperr.ErrConflict
		}
		attempts, err := q.ListAgentJobAttempts(ctx, job.ID)
		if err != nil {
			return err
		}
		matched := false
		for _, attempt := range attempts {
			if attempt.RunID == run.ID && attempt.AttemptNumber == req.Attempt &&
				pgUUID(attempt.LeaseToken).String() == req.LeaseToken && attempt.Status == "running" &&
				attempt.RuntimeGeneration == auth.AgentTokenVersionFromContext(ctx) &&
				attempt.LeaseExpiresAt.Time.After(time.Now()) {
				matched = true
			}
		}
		if !matched {
			return apperr.ErrConflict
		}
	} else if req.JobID != "" || req.Attempt != 0 || req.LeaseToken != "" {
		return apperr.ErrInvalidInput
	}
	if _, err := q.LockRunningRunForConnectorTransfer(ctx, dbq.LockRunningRunForConnectorTransferParams{ID: run.ID, AgentID: toPgUUID(appID)}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.ErrConflict
		}
		return err
	}
	run, err = q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: run.ID, AgentID: toPgUUID(appID)})
	if err != nil {
		return err
	}
	if run.RuntimeOwnerToken.Valid || run.Status != "running" || run.ExecutionKind == "prompt" {
		return apperr.Detail(apperr.ErrConflict, "run is not an active app invocation")
	}
	proof := execution.InvocationProofFromContext(ctx)
	if req.JobID != "" {
		proof.JobID, proof.Attempt, proof.LeaseToken = req.JobID, req.Attempt, req.LeaseToken
	}
	if err := execution.AuthorizeInvocationCompletion(ctx, q, appID, runID, auth.AgentTokenVersionFromContext(ctx), proof); err != nil {
		return err
	}
	actions, err := json.Marshal(req.Actions)
	if err != nil {
		return apperr.ErrInvalidInput
	}
	if req.Actions == nil {
		actions = []byte("[]")
	}
	jobID, leaseToken := uuid.Nil, uuid.Nil
	if req.JobID != "" {
		jobID, err = parseUUID(req.JobID)
		if err != nil {
			return apperr.ErrInvalidInput
		}
		leaseToken, err = parseUUID(req.LeaseToken)
		if err != nil {
			return apperr.ErrInvalidInput
		}
	}
	rows, err := q.CompleteAppRun(ctx, dbq.CompleteAppRunParams{
		RunID: run.ID, AgentID: toPgUUID(appID), TokenVersion: auth.AgentTokenVersionFromContext(ctx),
		JobID: toPgUUID(jobID), AttemptNumber: req.Attempt, LeaseToken: toPgUUID(leaseToken),
		Status: req.Status, ErrorMessage: req.Error, ErrorKind: req.ErrorKind,
		Actions: truncateActionsJSON(actions), StdoutLog: formatRunLogs(req.Logs), PanicTrace: req.PanicTrace,
	})
	if err != nil {
		return err
	}
	if rows != 1 {
		return apperr.ErrConflict
	}
	if err := q.UpdateRunLLMStats(ctx, run.ID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	runtimesvc.PublishRunTerminal(ctx, dbq.New(h.db.Pool()), h.pubsub, appID, runID, req.Status, req.Error)
	return nil
}

func (h *Service) GetCheckpoint(ctx context.Context, runID uuid.UUID) (json.RawMessage, error) {
	q := dbq.New(h.db.Pool())
	appID, err := h.admit(ctx, q)
	if err != nil {
		return nil, err
	}
	run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: toPgUUID(runID), AgentID: toPgUUID(appID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if run.RuntimeOwnerToken.Valid || run.TriggerType == "prompt" {
		return nil, apperr.ErrForbidden
	}
	if _, err := h.ResolveRun(ctx, runID); err != nil {
		return nil, err
	}
	if len(run.Checkpoint) == 0 {
		return json.RawMessage("null"), nil
	}
	return run.Checkpoint, nil
}

func formatRunLogs(logs []wire.LogEntry) string {
	parts := make([]string, len(logs))
	for i, entry := range logs {
		switch entry.Level {
		case wire.LogLevelDebug, wire.LogLevelWarn, wire.LogLevelError:
			parts[i] = "[" + string(entry.Level) + "] " + entry.Message
		default:
			parts[i] = entry.Message
		}
	}
	return strings.Join(parts, "\n")
}

func (h *Service) Upgrade(ctx context.Context, req wire.UpgradeRequest) error {
	if strings.TrimSpace(req.Description) == "" {
		return apperr.ErrInvalidInput
	}
	q := dbq.New(h.db.Pool())
	appID, err := h.admit(ctx, q)
	if err != nil {
		return err
	}
	runID, err := parseUUID(req.RunID)
	if err != nil {
		return apperr.ErrInvalidInput
	}
	admitted, err := execution.ResolveInvocation(ctx, q, appID, runID, auth.AgentTokenVersionFromContext(ctx), execution.InvocationProofFromContext(ctx))
	if err != nil {
		return err
	}
	if !authz.AccessAtLeast(agentsdk.Access(admitted.Runtime.Caller.Access), authz.RequiredAgentAccess(authz.AgentBuildManage)) {
		return apperr.ErrForbidden
	}
	if err := authz.Authorize(ctx, q, admitted.Principal, authz.AgentBuildManage, appID); err != nil {
		return err
	}
	origin, err := systemchat.CaptureHostedAsyncOrigin(ctx, q, appID, runID)
	if err != nil {
		return err
	}
	if err := h.builder.AcquireUpgradeLock(ctx, appID.String()); err != nil {
		if errors.Is(err, builder.ErrUpgradeInProgress) {
			return apperr.ErrConflict
		}
		return err
	}
	input := builder.UpgradeInput{ChatOriginID: origin, AgentID: appID.String(), Reason: "llm_request", Description: req.Description,
		ConversationID: admitted.Runtime.ConversationID, InitiatorUserID: admitted.Run.CallerUserID}
	go h.builder.RunUpgrade(context.Background(), input)
	return nil
}
