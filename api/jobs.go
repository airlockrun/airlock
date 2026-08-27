package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	jobssvc "github.com/airlockrun/airlock/service/jobs"
	"github.com/go-chi/chi/v5"
)

type jobsHandler struct {
	svc *jobssvc.Service
}

func newJobsHandler(svc *jobssvc.Service) *jobsHandler {
	if svc == nil {
		panic("api: jobs.Service is required")
	}
	return &jobsHandler{svc: svc}
}

func (h *jobsHandler) ListHandlers(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	handlers, err := h.svc.ListHandlers(r.Context(), principalFromRequest(r), agentID)
	if err != nil {
		writeJobsError(w, err)
		return
	}
	items := make([]*airlockv1.JobHandlerInfo, len(handlers))
	for i, handler := range handlers {
		items[i] = convert.JobHandlerToProto(handler)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListJobHandlersResponse{Handlers: items})
}

func (h *jobsHandler) ListJobs(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	query := r.URL.Query()
	options, err := jobssvc.ParseListOptions(query["limit"], query["cursor"])
	if err != nil {
		writeJobsError(w, err)
		return
	}
	page, err := h.svc.List(r.Context(), principalFromRequest(r), agentID, options)
	if err != nil {
		writeJobsError(w, err)
		return
	}
	items := make([]*airlockv1.JobInfo, len(page.Jobs))
	for i, job := range page.Jobs {
		items[i] = convert.JobToProto(job, false)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListJobsResponse{Jobs: items, NextCursor: page.NextCursor})
}

func (h *jobsHandler) ListBuildBlockers(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	buildID, err := parseUUID(chi.URLParam(r, "buildID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid build ID")
		return
	}
	query := r.URL.Query()
	options, err := jobssvc.ParseListOptions(query["limit"], query["cursor"])
	if err != nil {
		writeJobsError(w, err)
		return
	}
	page, err := h.svc.ListBuildBlockers(r.Context(), principalFromRequest(r), agentID, buildID, options)
	if err != nil {
		writeJobsError(w, err)
		return
	}
	items := make([]*airlockv1.JobInfo, len(page.Jobs))
	for i, job := range page.Jobs {
		items[i] = convert.JobToProto(job, false)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListJobsResponse{Jobs: items, NextCursor: page.NextCursor})
}

func (h *jobsHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := parseUUID(chi.URLParam(r, "jobID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}
	result, err := h.svc.Get(r.Context(), principalFromRequest(r), jobID)
	if err != nil {
		writeJobsError(w, err)
		return
	}
	attempts := make([]*airlockv1.JobAttemptInfo, len(result.Attempts))
	for i, attempt := range result.Attempts {
		attempts[i] = convert.JobAttemptToProto(attempt)
	}
	writeProto(w, http.StatusOK, &airlockv1.GetJobResponse{Job: convert.JobToProto(result.Job, true), Attempts: attempts})
}

func (h *jobsHandler) CancelJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := parseUUID(chi.URLParam(r, "jobID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}
	if _, err := h.svc.Cancel(r.Context(), principalFromRequest(r), jobID); err != nil {
		writeJobsError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *jobsHandler) RetryJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := parseUUID(chi.URLParam(r, "jobID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid job ID")
		return
	}
	job, err := h.svc.Retry(r.Context(), principalFromRequest(r), jobID)
	if err != nil {
		writeJobsError(w, err)
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.RetryJobResponse{Job: convert.JobToProto(job, true)})
}

func writeJobsError(w http.ResponseWriter, err error) {
	message := "job operation failed"
	switch {
	case errors.Is(err, service.ErrNotFound):
		message = "job not found"
	case errors.Is(err, service.ErrConflict), errors.Is(err, service.ErrInvalidInput):
		message = err.Error()
	}
	writeError(w, service.HTTPStatus(err), message)
}
