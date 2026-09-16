// Package hostapi implements the authenticated airlock-host control-plane protocol.
package hostapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/auth/lockout"
	"github.com/airlockrun/airlock/service"
	connectororchestrationsvc "github.com/airlockrun/airlock/service/connectororchestration"
	hostssvc "github.com/airlockrun/airlock/service/hosts"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Handler struct {
	hosts         *hostssvc.Service
	orchestration *connectororchestrationsvc.Service
	logger        *zap.Logger
	mu            sync.Mutex
	stopping      bool
	sessions      map[uuid.UUID]context.CancelFunc
	sessionsDone  sync.WaitGroup
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
	return &Handler{hosts: hosts, orchestration: orchestration, logger: logger, sessions: make(map[uuid.UUID]context.CancelFunc)}
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
	write(w, http.StatusOK, deviceCodeResponse{DeviceSecret: enrollment.DeviceSecret, UserCode: enrollment.UserCode, VerificationURL: enrollment.VerifyURL, ExpiresAt: enrollment.ExpiresAt, PollIntervalSeconds: int(enrollment.PollInterval)})
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
