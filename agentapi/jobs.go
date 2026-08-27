package agentapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	jobssvc "github.com/airlockrun/airlock/service/jobs"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const maxEnqueueJobBodyBytes = 80 * 1024

const maxJobProgressBodyBytes = 8 * 1024

func (h *Handler) EnqueueJob(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxEnqueueJobBodyBytes)
	var request wire.EnqueueJobRequest
	if err := readJSON(r, &request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid job request")
		return
	}
	jobID, err := canonicalJobUUID(request.ID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid job ID")
		return
	}
	sourceRunID, err := canonicalJobUUID(r.Header.Get("X-Airlock-Run-ID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "X-Airlock-Run-ID must identify the active source run")
		return
	}
	agentID := auth.AgentIDFromContext(r.Context())
	result, err := h.jobs.Enqueue(r.Context(), jobssvc.EnqueueRequest{
		ID:                jobID,
		AgentID:           agentID,
		RuntimeGeneration: auth.AgentTokenVersionFromContext(r.Context()),
		SourceRunID:       sourceRunID,
		HandlerName:       request.Name,
		HandlerVersion:    request.Version,
		InputSchemaHash:   request.InputSchemaHash,
		OutputSchemaHash:  request.OutputSchemaHash,
		Input:             request.Input,
		ScheduledAt:       request.ScheduledAt,
	})
	if err != nil {
		writeAgentJobError(w, err)
		return
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, wire.EnqueueJobResponse{Job: jobToWire(result.Job), Created: result.Created})
}

func (h *Handler) GetJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := canonicalJobUUID(chi.URLParam(r, "jobID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid job ID")
		return
	}
	result, err := h.jobs.GetForAgent(r.Context(), auth.AgentIDFromContext(r.Context()), jobID)
	if err != nil {
		writeAgentJobError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.GetJobResponse{Job: jobToWire(result.Job)})
}

func (h *Handler) ListJobs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	options, err := jobssvc.ParseListOptions(query["limit"], query["cursor"])
	if err != nil {
		writeAgentJobError(w, err)
		return
	}
	page, err := h.jobs.ListForAgent(r.Context(), auth.AgentIDFromContext(r.Context()), options)
	if err != nil {
		writeAgentJobError(w, err)
		return
	}
	items := make([]wire.JobInfo, len(page.Jobs))
	for i, job := range page.Jobs {
		items[i] = jobToWire(job)
	}
	writeJSON(w, http.StatusOK, wire.ListJobsResponse{Jobs: items, NextCursor: page.NextCursor})
}

func (h *Handler) UpdateJobProgress(w http.ResponseWriter, r *http.Request) {
	jobID, err := canonicalJobUUID(chi.URLParam(r, "jobID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid job ID")
		return
	}
	runID, err := canonicalJobUUID(r.Header.Get("X-Airlock-Run-ID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "X-Airlock-Run-ID must be canonical")
		return
	}
	leaseToken, err := canonicalJobUUID(r.Header.Get("X-Airlock-Job-Lease-Token"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "X-Airlock-Job-Lease-Token must be canonical")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJobProgressBodyBytes)
	var request wire.UpdateJobProgressRequest
	if err := readJSON(r, &request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid job progress request")
		return
	}
	err = h.jobs.UpdateProgress(r.Context(), jobssvc.ProgressRequest{
		JobID: jobID, AgentID: auth.AgentIDFromContext(r.Context()),
		RuntimeGeneration: auth.AgentTokenVersionFromContext(r.Context()), RunID: runID, LeaseToken: leaseToken,
		Attempt: request.Attempt, Phase: request.Phase, Message: request.Message, Completed: request.Completed, Total: request.Total,
	})
	if err != nil {
		writeAgentJobError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) CancelJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := canonicalJobUUID(chi.URLParam(r, "jobID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid job ID")
		return
	}
	if _, err := h.jobs.CancelForAgent(r.Context(), auth.AgentIDFromContext(r.Context()), jobID); err != nil {
		writeAgentJobError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func jobToWire(job dbq.AgentJob) wire.JobInfo {
	return wire.JobInfo{
		ID:               pgUUID(job.ID).String(),
		AgentID:          pgUUID(job.AgentID).String(),
		HandlerName:      job.HandlerName,
		HandlerVersion:   job.HandlerVersion,
		InputSchemaHash:  job.InputSchemaHash,
		OutputSchemaHash: job.OutputSchemaHash,
		Status:           job.Status,
		Input:            job.InputPayload,
		Output:           job.OutputPayload,
		AttemptCount:     job.AttemptCount,
		MaxAttempts:      job.MaxAttempts,
		AttemptLimit:     job.AttemptLimit,
		Progress:         jobProgressToWire(job),
		LastError:        job.LastError.String,
		SourceRunID:      optionalJobUUID(job.SourceRunID),
		ScheduledAt:      optionalJobTime(job.ScheduledAt),
		CreatedAt:        job.CreatedAt.Time,
		UpdatedAt:        job.UpdatedAt.Time,
		StartedAt:        optionalJobTime(job.StartedAt),
		CompletedAt:      optionalJobTime(job.CompletedAt),
	}
}

func jobProgressToWire(job dbq.AgentJob) *wire.JobProgress {
	if !job.ProgressPhase.Valid {
		return nil
	}
	return &wire.JobProgress{
		Phase: job.ProgressPhase.String, Message: job.ProgressMessage.String,
		Completed: job.ProgressCompleted.Int64, Total: job.ProgressTotal.Int64,
	}
}

func optionalJobUUID(value pgtype.UUID) string {
	if !value.Valid {
		return ""
	}
	return pgUUID(value).String()
}

func optionalJobTime(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time
	return &result
}

func canonicalJobUUID(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return uuid.Nil, errors.New("UUID must be canonical and non-nil")
	}
	return id, nil
}

func writeAgentJobError(w http.ResponseWriter, err error) {
	var candidateErr *jobssvc.CandidateContractError
	if errors.As(err, &candidateErr) {
		writeJSON(w, http.StatusConflict, wire.EnqueueJobErrorResponse{
			Code:           wire.EnqueueJobErrorCodeUnavailable,
			Error:          candidateErr.Error(),
			HandlerName:    candidateErr.HandlerName,
			HandlerVersion: candidateErr.HandlerVersion,
		})
		return
	}
	message := "job operation failed"
	switch {
	case errors.Is(err, service.ErrInvalidInput):
		message = err.Error()
	case errors.Is(err, service.ErrNotFound):
		message = "job not found"
	case errors.Is(err, service.ErrConflict):
		message = err.Error()
	}
	writeJSONError(w, service.HTTPStatus(err), message)
}
