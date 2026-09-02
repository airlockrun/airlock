// Package hostapi implements the authenticated airlock-host control-plane protocol.
package hostapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/auth/lockout"
	"github.com/airlockrun/airlock/service"
	connectororchestrationsvc "github.com/airlockrun/airlock/service/connectororchestration"
	hostssvc "github.com/airlockrun/airlock/service/hosts"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Handler struct {
	hosts         *hostssvc.Service
	orchestration *connectororchestrationsvc.Service
	logger        *zap.Logger
}

type enrollmentRequest struct {
	DeviceSecret string `json:"deviceSecret"`
}

type deviceCodeResponse struct {
	DeviceSecret        string    `json:"deviceSecret"`
	UserCode            string    `json:"userCode"`
	VerificationURL     string    `json:"verificationUrl"`
	ExpiresAt           time.Time `json:"expiresAt"`
	PollIntervalSeconds int       `json:"pollIntervalSeconds"`
}

type enrollmentResponse struct {
	Status     string `json:"status"`
	HostID     string `json:"hostId,omitempty"`
	Credential string `json:"credential,omitempty"`
	Error      string `json:"error,omitempty"`
}

func New(hosts *hostssvc.Service, orchestration *connectororchestrationsvc.Service, logger *zap.Logger) *Handler {
	if hosts == nil || orchestration == nil || logger == nil {
		panic("hostapi: nil dependency")
	}
	return &Handler{hosts: hosts, orchestration: orchestration, logger: logger}
}

func (h *Handler) Begin(w http.ResponseWriter, r *http.Request) {
	var info protocol.HostInfo
	if !decode(w, r, 16<<10, &info) {
		return
	}
	enrollment, err := h.hosts.BeginEnrollment(r.Context(), lockout.NormalizeIP(r.RemoteAddr), info)
	if errors.Is(err, hostssvc.ErrEnrollmentRateLimited) {
		w.Header().Set("Retry-After", "3600")
		http.Error(w, "too many host enrollment attempts", http.StatusTooManyRequests)
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	write(w, http.StatusOK, deviceCodeResponse{
		DeviceSecret: enrollment.DeviceSecret, UserCode: enrollment.UserCode,
		VerificationURL: enrollment.VerifyURL, ExpiresAt: enrollment.ExpiresAt,
		PollIntervalSeconds: int(enrollment.PollInterval),
	})
}

func (h *Handler) CompleteEnrollment(w http.ResponseWriter, r *http.Request) {
	var request enrollmentRequest
	if !decode(w, r, 4<<10, &request) {
		return
	}
	result, err := h.hosts.CompleteEnrollment(r.Context(), request.DeviceSecret)
	if errors.Is(err, hostssvc.ErrSlowDown) {
		write(w, http.StatusOK, enrollmentResponse{Status: "pending", Error: "slow_down"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	write(w, http.StatusOK, enrollmentResponse{Status: result.Status, HostID: result.HostID.String(), Credential: result.Credential})
}

func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var request protocol.HostSyncRequest
	if !decode(w, r, protocol.MaxChildFrameBytes, &request) {
		return
	}
	if _, err := h.hosts.Sync(r.Context(), identity.HostID, request); err != nil {
		writeError(w, err)
		return
	}
	for _, connector := range request.Connectors {
		if connector.Readiness != protocol.ReadinessReady {
			continue
		}
		connectorID, err := uuid.Parse(connector.InstallationID)
		if err == nil {
			if err := h.orchestration.AdvanceConnector(r.Context(), connectorID); err != nil {
				h.logger.Error("advance hosted connector orchestration", zap.String("connector_id", connectorID.String()), zap.Error(err))
			}
		}
	}
	write(w, http.StatusOK, protocol.HostSyncResponse{HostID: identity.HostID.String(), HeartbeatSeconds: 20, LongPollSeconds: 25})
}

func (h *Handler) ConnectorInventory(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var request protocol.HostConnectorInventoryMutationRequest
	if !decode(w, r, protocol.MaxHostInventoryMutationBytes, &request) {
		return
	}
	if err := protocol.ValidateHostConnectorInventoryMutationRequest(request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	response, err := h.hosts.ReconcileInventory(r.Context(), identity.HostID, request)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := protocol.ValidateHostConnectorInventoryMutationResponse(response); err != nil {
		h.logger.Error("invalid host connector inventory response", zap.Error(err))
		http.Error(w, "host service unavailable", http.StatusInternalServerError)
		return
	}
	write(w, http.StatusOK, response)
}

func parseAttempts(values []protocol.ActiveAttempt) ([]hostssvc.ActiveAttempt, error) {
	out := make([]hostssvc.ActiveAttempt, len(values))
	for i, value := range values {
		jobID, jobErr := uuid.Parse(value.JobID)
		token, tokenErr := uuid.Parse(value.AttemptToken)
		if jobErr != nil || tokenErr != nil {
			return nil, errors.New("invalid active attempt")
		}
		out[i] = hostssvc.ActiveAttempt{JobID: jobID, AttemptToken: token}
	}
	return out, nil
}

func (h *Handler) Poll(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var request protocol.HostPollRequest
	if !decode(w, r, 64<<10, &request) {
		return
	}
	management, err := parseAttempts(request.ActiveManagementAttempts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	connectors, err := parseAttempts(request.ActiveConnectorAttempts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.hosts.RenewManagementAttempts(r.Context(), identity.HostID, management); err != nil {
		writeError(w, err)
		return
	}
	if err := h.hosts.RenewConnectorAttempts(r.Context(), identity.HostID, connectors); err != nil {
		writeError(w, err)
		return
	}
	claimConnector := len(connectors) < protocol.MaxActiveAttempts
	cancellations, err := h.hosts.Cancellations(r.Context(), identity.HostID)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(cancellations) > 0 {
		work := make([]protocol.HostWork, 0, len(cancellations)+1)
		for _, cancellation := range cancellations {
			work = append(work, protocol.HostWork{
				Kind: protocol.HostWorkConnectorCancel, ConnectorID: cancellation.ConnectorID.String(),
				Cancel: &protocol.ChildCancel{JobID: cancellation.JobID.String(), AttemptToken: cancellation.AttemptToken.String()},
			})
		}
		claimed, claimErr := h.hosts.ClaimWork(r.Context(), identity.HostID, claimConnector)
		if claimErr != nil {
			writeError(w, claimErr)
			return
		}
		if claimed != nil {
			work = append(work, *claimed)
		}
		write(w, http.StatusOK, protocol.HostPollResponse{Work: work})
		return
	}
	work, err := h.hosts.WaitForWork(r.Context(), identity.HostID, claimConnector, 25*time.Second)
	if err != nil {
		writeError(w, err)
		return
	}
	if work == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	write(w, http.StatusOK, protocol.HostPollResponse{Work: []protocol.HostWork{*work}})
}

func (h *Handler) ManagementEvent(w http.ResponseWriter, r *http.Request) {
	identity, jobID, ok := h.jobAuth(w, r)
	if !ok {
		return
	}
	var event protocol.HostManagementEvent
	if !decode(w, r, 80<<10, &event) {
		return
	}
	_, err := h.hosts.AppendManagementEvent(r.Context(), identity.HostID, jobID, event)
	if err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ManagementComplete(w http.ResponseWriter, r *http.Request) {
	identity, jobID, ok := h.jobAuth(w, r)
	if !ok {
		return
	}
	var completion protocol.HostManagementCompletion
	if !decode(w, r, 1<<20, &completion) {
		return
	}
	_, err := h.hosts.CompleteManagement(r.Context(), identity.HostID, jobID, completion)
	if err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ConnectorEvent(w http.ResponseWriter, r *http.Request) {
	identity, connectorID, jobID, ok := h.connectorJobAuth(w, r)
	if !ok {
		return
	}
	var event protocol.JobEvent
	if !decode(w, r, 80<<10, &event) {
		return
	}
	if err := h.hosts.AppendConnectorEvent(r.Context(), identity.HostID, connectorID, jobID, event); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ConnectorComplete(w http.ResponseWriter, r *http.Request) {
	identity, connectorID, jobID, ok := h.connectorJobAuth(w, r)
	if !ok {
		return
	}
	var completion protocol.JobCompletion
	if !decode(w, r, 1<<20, &completion) {
		return
	}
	job, err := h.hosts.CompleteConnector(r.Context(), identity.HostID, connectorID, jobID, completion)
	if err != nil {
		writeError(w, err)
		return
	}
	if job.OrchestrationID.Valid {
		if _, err := h.orchestration.AdvanceSystem(r.Context(), uuid.UUID(job.OrchestrationID.Bytes)); err != nil {
			h.logger.Error("advance hosted connector orchestration", zap.Error(err))
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (hostssvc.Identity, bool) {
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return hostssvc.Identity{}, false
	}
	identity, err := h.hosts.Authenticate(r.Context(), strings.TrimPrefix(authorization, "Bearer "))
	if err != nil {
		if !errors.Is(err, service.ErrUnauthorized) {
			h.logger.Error("host authentication infrastructure failure", zap.Error(err))
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return hostssvc.Identity{}, false
	}
	return identity, true
}

func (h *Handler) jobAuth(w http.ResponseWriter, r *http.Request) (hostssvc.Identity, uuid.UUID, bool) {
	identity, ok := h.authenticate(w, r)
	if !ok {
		return hostssvc.Identity{}, uuid.Nil, false
	}
	jobID, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		http.Error(w, "invalid job ID", http.StatusBadRequest)
		return hostssvc.Identity{}, uuid.Nil, false
	}
	return identity, jobID, true
}

func (h *Handler) connectorJobAuth(w http.ResponseWriter, r *http.Request) (hostssvc.Identity, uuid.UUID, uuid.UUID, bool) {
	identity, jobID, ok := h.jobAuth(w, r)
	if !ok {
		return hostssvc.Identity{}, uuid.Nil, uuid.Nil, false
	}
	connectorID, err := uuid.Parse(chi.URLParam(r, "connectorID"))
	if err != nil {
		http.Error(w, "invalid connector ID", http.StatusBadRequest)
		return hostssvc.Identity{}, uuid.Nil, uuid.Nil, false
	}
	return identity, connectorID, jobID, true
}

func decode(w http.ResponseWriter, r *http.Request, limit int64, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	status := service.HTTPStatus(err)
	if status < 400 {
		status = http.StatusInternalServerError
	}
	message := err.Error()
	if status >= 500 {
		message = "host service unavailable"
	}
	http.Error(w, message, status)
}
