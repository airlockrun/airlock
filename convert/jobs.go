package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

func JobHandlerToProto(handler dbq.AgentJobHandler) *airlockv1.JobHandlerInfo {
	return &airlockv1.JobHandlerInfo{
		AgentId:           PgUUIDToString(handler.AgentID),
		Name:              handler.Name,
		Version:           handler.Version,
		Description:       handler.Description,
		TimeoutMs:         handler.TimeoutMs,
		MaxAttempts:       handler.MaxAttempts,
		MaxConcurrency:    handler.MaxConcurrency,
		InputSchema:       JSONToStruct(handler.InputSchema),
		OutputSchema:      JSONToStruct(handler.OutputSchema),
		InputSchemaHash:   handler.InputSchemaHash,
		OutputSchemaHash:  handler.OutputSchemaHash,
		Active:            handler.Active,
		RuntimeGeneration: handler.AgentTokenVersion,
		CreatedAt:         PgTimestampToProto(handler.CreatedAt),
		UpdatedAt:         PgTimestampToProto(handler.UpdatedAt),
	}
}

func JobToProto(job dbq.AgentJob, detail bool) *airlockv1.JobInfo {
	info := &airlockv1.JobInfo{
		Id:                PgUUIDToString(job.ID),
		AgentId:           PgUUIDToString(job.AgentID),
		HandlerName:       job.HandlerName,
		HandlerVersion:    job.HandlerVersion,
		SourceRunId:       PgUUIDToString(job.SourceRunID),
		InitiatorKind:     job.InitiatorKind,
		InitiatorUserId:   PgUUIDToString(job.InitiatorUserID),
		InitiatorAccess:   job.InitiatorAccess,
		Status:            job.Status,
		TimeoutMs:         job.TimeoutMs,
		MaxAttempts:       job.MaxAttempts,
		AttemptLimit:      job.AttemptLimit,
		AttemptCount:      job.AttemptCount,
		Progress:          JobProgressToProto(job),
		StateVersion:      job.StateVersion,
		NextAttemptAt:     PgTimestampToProto(job.NextAttemptAt),
		LastError:         job.LastError.String,
		CancelRequestedAt: PgTimestampToProto(job.CancelRequestedAt),
		StartedAt:         PgTimestampToProto(job.StartedAt),
		CompletedAt:       PgTimestampToProto(job.CompletedAt),
		CreatedAt:         PgTimestampToProto(job.CreatedAt),
		UpdatedAt:         PgTimestampToProto(job.UpdatedAt),
		CronId:            PgUUIDToString(job.CronID),
		CronSlug:          job.CronSlug.String,
		ScheduledAt:       PgTimestampToProto(job.ScheduledAt),
	}
	if detail {
		info.InputJson = string(job.InputPayload)
		info.OutputJson = string(job.OutputPayload)
	}
	return info
}

func JobProgressToProto(job dbq.AgentJob) *airlockv1.JobProgressInfo {
	if !job.ProgressPhase.Valid {
		return nil
	}
	return &airlockv1.JobProgressInfo{
		Phase: job.ProgressPhase.String, Message: job.ProgressMessage.String,
		Completed: job.ProgressCompleted.Int64, Total: job.ProgressTotal.Int64,
		Attempt: job.ProgressAttempt.Int32, UpdatedAt: PgTimestampToProto(job.ProgressUpdatedAt),
	}
}

func JobAttemptToProto(attempt dbq.AgentJobAttempt) *airlockv1.JobAttemptInfo {
	return &airlockv1.JobAttemptInfo{
		JobId:             PgUUIDToString(attempt.JobID),
		AttemptNumber:     attempt.AttemptNumber,
		Status:            attempt.Status,
		RuntimeGeneration: attempt.RuntimeGeneration,
		RunId:             PgUUIDToString(attempt.RunID),
		ErrorKind:         attempt.ErrorKind.String,
		ErrorMessage:      attempt.ErrorMessage.String,
		LeasedAt:          PgTimestampToProto(attempt.LeasedAt),
		StartedAt:         PgTimestampToProto(attempt.StartedAt),
		CompletedAt:       PgTimestampToProto(attempt.CompletedAt),
		LeaseExpiresAt:    PgTimestampToProto(attempt.LeaseExpiresAt),
	}
}
