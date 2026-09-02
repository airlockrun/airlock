package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	connectorjobssvc "github.com/airlockrun/airlock/service/connectorjobs"
	connectororchestrationsvc "github.com/airlockrun/airlock/service/connectororchestration"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (h *Handler) ConnectorCommand(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	needSlug, operation := chi.URLParam(r, "needSlug"), chi.URLParam(r, "operation")
	var request protocol.CommandCallRequest
	if err := readJSON(r, &request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if request.Mode != protocol.CommandModeUnary {
		writeJSONError(w, http.StatusBadRequest, "unary connector command requires unary mode")
		return
	}
	timeout, ok := connectorTimeout(request.Deadline)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid connector command deadline")
		return
	}
	job, err := h.connectorJobs.Enqueue(r.Context(), agentID, needSlug, uuid.New(), operation, string(protocol.CommandModeUnary), int32(request.Revision), request.InputSchemaHash, request.OutputSchemaHash, request.Input, timeout)
	if err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	jobID := uuid.UUID(job.ID.Bytes)
	job, err = h.connectorJobs.Wait(r.Context(), agentID, jobID)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			defer cancel()
			_, _ = h.connectorJobs.CancelForNeed(cancelCtx, agentID, jobID, needSlug)
			return
		}
		writeConnectorServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorCommandResponse(job))
}

func (h *Handler) StartConnectorJob(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	needSlug, operation := chi.URLParam(r, "needSlug"), chi.URLParam(r, "operation")
	var request protocol.CommandCallRequest
	if err := readJSON(r, &request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if request.Mode != protocol.CommandModeJob {
		writeJSONError(w, http.StatusBadRequest, "long connector command requires job mode")
		return
	}
	requestID, err := uuid.Parse(request.RequestID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "connector request ID must be a UUID")
		return
	}
	timeout, ok := connectorTimeout(request.Deadline)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid connector command deadline")
		return
	}
	job, err := h.connectorJobs.Enqueue(r.Context(), agentID, needSlug, requestID, operation, string(protocol.CommandModeJob), int32(request.Revision), request.InputSchemaHash, request.OutputSchemaHash, request.Input, timeout)
	if err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, connectorCommandResponse(job))
}

func (h *Handler) GetConnectorJob(w http.ResponseWriter, r *http.Request) {
	needSlug := chi.URLParam(r, "needSlug")
	jobID, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid connector job ID")
		return
	}
	detail, err := h.connectorJobs.DetailForNeed(r.Context(), auth.AgentIDFromContext(r.Context()), jobID, needSlug)
	if err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectorJobResponse(detail))
}

func (h *Handler) CancelConnectorJob(w http.ResponseWriter, r *http.Request) {
	needSlug := chi.URLParam(r, "needSlug")
	jobID, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid connector job ID")
		return
	}
	if _, err := h.connectorJobs.CancelForNeed(r.Context(), auth.AgentIDFromContext(r.Context()), jobID, needSlug); err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) CreateConnectorOrchestration(w http.ResponseWriter, r *http.Request) {
	var request wire.ConnectorOrchestrationRequest
	if err := readJSON(r, &request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resourceIDs := make([]uuid.UUID, len(request.Request.Targets.ResourceIDs))
	for i, raw := range request.Request.Targets.ResourceIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid connector target ID")
			return
		}
		resourceIDs[i] = id
	}
	requestID, err := uuid.Parse(request.Request.RequestID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "orchestration request ID must be a UUID")
		return
	}
	deadline := time.Now().Add(time.Hour)
	if request.Request.Deadline != nil {
		deadline = *request.Request.Deadline
	}
	maxConcurrency := int32(request.Request.MaxConcurrency)
	if maxConcurrency == 0 {
		maxConcurrency = 10
	}
	batchSize := int32(request.Request.BatchSize)
	if batchSize == 0 {
		batchSize = 1
	}
	detail, err := h.connectorOrchestration.CreateFromAgent(r.Context(), connectororchestrationsvc.CreateRequest{
		AgentID: auth.AgentIDFromContext(r.Context()), NeedSlug: chi.URLParam(r, "needSlug"), Command: request.CommandName,
		Input: request.Request.Command.Input, Strategy: string(request.Request.Strategy), OfflinePolicy: string(request.Request.OfflinePolicy),
		RequestID: requestID, MaxConcurrency: maxConcurrency, BatchSize: batchSize, CanaryCount: int32(request.Request.CanaryCount), Quorum: int32(request.Request.Quorum),
		Deadline: deadline, ResourceIDs: resourceIDs, Labels: request.Request.Targets.Labels,
		Revision: int32(request.Request.Command.Revision), Mode: string(request.Request.Command.Mode), InputHash: request.Request.Command.InputSchemaHash, OutputHash: request.Request.Command.OutputSchemaHash,
	})
	if err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	response, err := h.connectorOrchestrationResponse(r.Context(), chi.URLParam(r, "needSlug"), detail)
	if err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, response)
}

func (h *Handler) GetConnectorOrchestration(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "orchestrationID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid connector orchestration ID")
		return
	}
	needSlug := chi.URLParam(r, "needSlug")
	detail, err := h.connectorOrchestration.GetFromAgent(r.Context(), auth.AgentIDFromContext(r.Context()), needSlug, id)
	if err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	response, err := h.connectorOrchestrationResponse(r.Context(), needSlug, detail)
	if err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) CancelConnectorOrchestration(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "orchestrationID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid connector orchestration ID")
		return
	}
	if err := h.connectorOrchestration.CancelFromAgent(r.Context(), auth.AgentIDFromContext(r.Context()), chi.URLParam(r, "needSlug"), id); err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) connectorOrchestrationResponse(ctx context.Context, needSlug string, detail connectororchestrationsvc.Detail) (wire.ConnectorOrchestrationInfo, error) {
	row := detail.Orchestration
	result := wire.ConnectorOrchestrationInfo{
		ID: uuid.UUID(row.ID.Bytes).String(), Status: connectorStatus(row.Status), Strategy: row.Strategy,
		CanaryPhase: row.CanaryPhase, CanaryCount: row.CanaryCount, CanarySucceededCount: row.CanarySucceededCount,
		Targets: make([]wire.ConnectorJobInfo, 0, len(detail.Jobs)),
	}
	for _, job := range detail.Jobs {
		jobDetail, err := h.connectorJobs.DetailForNeed(ctx, uuid.UUID(row.AgentID.Bytes), uuid.UUID(job.ID.Bytes), needSlug)
		if err != nil {
			return wire.ConnectorOrchestrationInfo{}, err
		}
		item := connectorJobResponse(jobDetail)
		item.ResourceID = uuid.UUID(job.ConnectorID.Bytes).String()
		result.Targets = append(result.Targets, item)
	}
	return result, nil
}

func connectorTimeout(deadline *time.Time) (time.Duration, bool) {
	if deadline == nil {
		return 2 * time.Minute, true
	}
	timeout := time.Until(*deadline)
	return timeout, timeout > 0 && timeout <= 24*time.Hour
}

func connectorCommandResponse(job dbq.ConnectorJob) protocol.CommandCallResponse {
	response := protocol.CommandCallResponse{JobID: uuid.UUID(job.ID.Bytes).String(), Status: connectorStatus(job.Status)}
	if job.Status == "succeeded" {
		response.Output = job.OutputPayload
	}
	if job.ErrorMessage.Valid {
		response.Error = job.ErrorMessage.String
	}
	return response
}

func connectorJobResponse(detail connectorjobssvc.Detail) wire.ConnectorJobInfo {
	job := detail.Job
	response := wire.ConnectorJobInfo{
		JobID: uuid.UUID(job.ID.Bytes).String(), Status: connectorStatus(job.Status), Output: job.OutputPayload,
		Error: job.ErrorMessage.String, History: make([]wire.ConnectorJobProgress, 0, len(detail.Events)),
	}
	for _, event := range detail.Events {
		if event.Kind != "progress" {
			continue
		}
		var progress protocol.JobEvent
		if json.Unmarshal(event.Payload, &progress) != nil {
			continue
		}
		item := wire.ConnectorJobProgress{Sequence: event.Sequence, AttemptSequence: event.AttemptSequence, Phase: progress.Phase, Message: progress.Message, Completed: progress.Completed, Total: progress.Total, Time: progress.Time}
		response.History = append(response.History, item)
		response.Progress = &response.History[len(response.History)-1]
	}
	return response
}

func connectorStatus(status string) string {
	switch status {
	case "succeeded":
		return "success"
	case "failed":
		return "error"
	case "cancelled":
		return "canceled"
	case "skipped":
		return "error"
	default:
		return status
	}
}

func writeConnectorServiceError(w http.ResponseWriter, err error) {
	writeJSONError(w, service.HTTPStatus(err), err.Error())
}
