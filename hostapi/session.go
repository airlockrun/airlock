package hostapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/service"
	"github.com/coder/websocket"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Shutdown closes upgraded sockets explicitly; net/http does not own them.
func (h *Handler) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	h.stopping = true
	for _, cancel := range h.sessions {
		cancel()
	}
	h.mu.Unlock()
	done := make(chan struct{})
	go func() { h.sessionsDone.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	identity, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	supported := false
	for _, offered := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		if strings.TrimSpace(offered) == protocol.HostTransportProtocol {
			supported = true
		}
	}
	if !supported {
		http.Error(w, "unsupported host transport", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	if h.stopping {
		h.mu.Unlock()
		http.Error(w, "server stopping", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	id := uuid.New()
	h.sessions[id] = cancel
	h.sessionsDone.Add(1)
	h.mu.Unlock()
	defer func() { cancel(); h.mu.Lock(); delete(h.sessions, id); h.mu.Unlock(); h.sessionsDone.Done() }()
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.HostTransportProtocol}})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	if conn.Subprotocol() != protocol.HostTransportProtocol {
		return
	}
	conn.SetReadLimit(protocol.MaxHostMessageBytes)
	credential := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel()
	var demanding atomic.Bool
	var synchronized atomic.Bool
	var demandState hostDemandState
	slots := make(chan struct{}, protocol.MaxHostRequests)
	var pendingMu sync.Mutex
	pending := make(map[string]bool)
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				checkCtx, stop := context.WithTimeout(ctx, 5*time.Second)
				_, err := h.hosts.Authenticate(checkCtx, credential)
				stop()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		kind, data, err := conn.Read(ctx)
		if err != nil || kind != websocket.MessageText {
			return
		}
		message, err := protocol.DecodeHostMessage(data)
		if err != nil || message.Synced != nil || message.Inventoried != nil || message.Work != nil || message.Ack != nil || message.Error != nil {
			return
		}
		pendingMu.Lock()
		duplicate := pending[message.ID]
		pending[message.ID] = true
		pendingMu.Unlock()
		if duplicate {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			return
		}
		if message.Demand != nil && (!synchronized.Load() || !demanding.CompareAndSwap(false, true)) {
			return
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots; pendingMu.Lock(); delete(pending, message.ID); pendingMu.Unlock() }()
			requestCtx, stop := context.WithCancel(ctx)
			if message.Demand == nil {
				stop()
				requestCtx, stop = context.WithTimeout(ctx, 35*time.Second)
			}
			defer stop()
			response := protocol.HostMessage{Protocol: protocol.HostTransportProtocol, ID: message.ID}
			live, err := h.hosts.Authenticate(requestCtx, credential)
			if err == nil && live.HostID != identity.HostID {
				err = service.ErrUnauthorized
			}
			if err == nil {
				response, err = h.dispatch(requestCtx, identity.HostID, credential, message, &demandState)
			}
			if err != nil {
				code := service.HTTPStatus(err)
				text := err.Error()
				if code < 400 {
					code = 500
				}
				if code >= 500 {
					text = "host service unavailable"
				}
				response = protocol.HostMessage{Error: &protocol.HostMessageError{Code: code, Message: text}}
			} else if message.Sync != nil {
				synchronized.Store(true)
			}
			response.Protocol, response.ID = protocol.HostTransportProtocol, message.ID
			data, err := json.Marshal(response)
			if err != nil || len(data) > protocol.MaxHostMessageBytes {
				cancel()
				return
			}
			writeCtx, stopWrite := context.WithTimeout(ctx, 10*time.Second)
			if message.Demand != nil {
				demanding.Store(false)
			}
			err = conn.Write(writeCtx, websocket.MessageText, data)
			stopWrite()
			if err != nil {
				cancel()
			}
		}()
	}
}

// The session's single-demand admission serializes access to this delivery state.
type hostDemandState struct {
	cancellationSequence uint64
	claimFirst           bool
}

func (h *Handler) dispatch(ctx context.Context, hostID uuid.UUID, credential string, m protocol.HostMessage, demandState *hostDemandState) (protocol.HostMessage, error) {
	ack := protocol.HostMessage{Ack: &struct{}{}}
	switch {
	case m.Sync != nil:
		if _, err := h.hosts.Sync(ctx, hostID, *m.Sync); err != nil {
			return ack, err
		}
		for _, connector := range m.Sync.Connectors {
			if connector.Readiness == protocol.ReadinessReady {
				if id, err := uuid.Parse(connector.InstallationID); err == nil {
					if err := h.orchestration.AdvanceConnector(ctx, id); err != nil {
						h.logger.Error("advance hosted connector orchestration", zap.Error(err))
					}
				}
			}
		}
		return protocol.HostMessage{Synced: &protocol.HostSyncResponse{HostID: hostID.String(), HeartbeatSeconds: 20}}, nil
	case m.Inventory != nil:
		if err := protocol.ValidateHostConnectorInventoryMutationRequest(*m.Inventory); err != nil {
			return ack, service.Detail(service.ErrInvalidInput, "%s", err)
		}
		response, err := h.hosts.ReconcileInventory(ctx, hostID, *m.Inventory)
		return protocol.HostMessage{Inventoried: &response}, err
	case m.Heartbeat != nil:
		if err := h.hosts.Heartbeat(ctx, hostID, m.Heartbeat.AccessMode); err != nil {
			return ack, err
		}
		management, err := parseAttempts(m.Heartbeat.ActiveManagementAttempts)
		if err != nil {
			return ack, service.ErrInvalidInput
		}
		connectors, err := parseAttempts(m.Heartbeat.ActiveConnectorAttempts)
		if err != nil {
			return ack, service.ErrInvalidInput
		}
		if err := h.hosts.RenewManagementAttempts(ctx, hostID, management); err != nil {
			return ack, err
		}
		return ack, h.hosts.RenewConnectorAttempts(ctx, hostID, connectors)
	case m.Demand != nil:
		sub := h.hosts.SubscribeWork(hostID)
		defer sub.Close()
		for {
			if _, err := h.hosts.Authenticate(ctx, credential); err != nil {
				return ack, err
			}
			notices, err := h.hosts.Cancellations(ctx, hostID)
			if err != nil {
				return ack, err
			}
			if len(notices) == 0 || demandState.claimFirst {
				work, err := h.hosts.ClaimWork(ctx, hostID, m.Demand.ConnectorCapacity > 0)
				if err != nil {
					return ack, err
				}
				if work != nil {
					if _, err := h.hosts.Authenticate(ctx, credential); err != nil {
						return ack, err
					}
					demandState.claimFirst = false
					return protocol.HostMessage{Work: work}, nil
				}
			}
			if len(notices) > 0 {
				// Alternate cancellation and claims; rotate among unresponsive children.
				notice := notices[demandState.cancellationSequence%uint64(len(notices))]
				demandState.cancellationSequence++
				demandState.claimFirst = true
				return protocol.HostMessage{Work: &protocol.HostWork{Kind: protocol.HostWorkConnectorCancel, ConnectorID: notice.ConnectorID.String(), Cancel: &protocol.ChildCancel{JobID: notice.JobID.String(), AttemptToken: notice.AttemptToken.String()}}}, nil
			}
			waitCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			err = sub.Wait(waitCtx)
			stop()
			if m.Demand.ConnectorCapacity == 0 && ctx.Err() == nil {
				return ack, nil
			}
			if err != nil && (!errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil) {
				return ack, err
			}
		}
	case m.ManagementEvent != nil:
		id, err := uuid.Parse(m.ManagementEvent.JobID)
		if err != nil {
			return ack, service.ErrInvalidInput
		}
		_, err = h.hosts.AppendManagementEvent(ctx, hostID, id, m.ManagementEvent.Event)
		return ack, err
	case m.ManagementCompletion != nil:
		id, err := uuid.Parse(m.ManagementCompletion.JobID)
		if err != nil {
			return ack, service.ErrInvalidInput
		}
		_, err = h.hosts.CompleteManagement(ctx, hostID, id, *m.ManagementCompletion)
		return ack, err
	case m.ConnectorEvent != nil:
		connectorID, err1 := uuid.Parse(m.ConnectorEvent.ConnectorID)
		jobID, err2 := uuid.Parse(m.ConnectorEvent.JobID)
		if errors.Join(err1, err2) != nil {
			return ack, service.ErrInvalidInput
		}
		return ack, h.hosts.AppendConnectorEvent(ctx, hostID, connectorID, jobID, m.ConnectorEvent.Event)
	case m.ConnectorCompletion != nil:
		connectorID, err1 := uuid.Parse(m.ConnectorCompletion.ConnectorID)
		jobID, err2 := uuid.Parse(m.ConnectorCompletion.JobID)
		if errors.Join(err1, err2) != nil {
			return ack, service.ErrInvalidInput
		}
		job, err := h.hosts.CompleteConnector(ctx, hostID, connectorID, jobID, m.ConnectorCompletion.Completion)
		if err == nil && job.OrchestrationID.Valid {
			if _, err := h.orchestration.AdvanceSystem(ctx, uuid.UUID(job.OrchestrationID.Bytes)); err != nil {
				h.logger.Error("advance hosted connector orchestration", zap.Error(err))
			}
		}
		return ack, err
	default:
		return ack, service.ErrInvalidInput
	}
}
