package realtime

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/coder/websocket"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	sendBufferSize = 256
	writeTimeout   = 10 * time.Second
	pingInterval   = 30 * time.Second
)

// MessageHandler processes an inbound WebSocket message from a client.
type MessageHandler func(conn *Conn, env Envelope)

// Conn wraps a WebSocket connection with user identity and a send buffer.
type Conn struct {
	ID     string
	UserID uuid.UUID
	Email  string
	// TenantRole is fixed for the lifetime of the connection. The live
	// authorization monitor closes the connection if the user's role changes.
	TenantRole auth.Role
	// Identity is the immutable admission proof, installed before registration.
	Identity *auth.Identity
	// SinceSeq is the client's replay cursor from the ?since= connect
	// param: the lowest processed per-topic watermark. Set once by
	// the WS accept handler before the Subscribe loop; the hub replays
	// only seq>SinceSeq per topic (0 = fresh connect, no replay).
	SinceSeq   uint64
	ws         *websocket.Conn
	send       chan []byte
	sendMu     sync.Mutex
	overflowed bool
	disconnect context.CancelFunc
	logger     *zap.Logger
	jobsMu     sync.RWMutex
	jobAgents  map[uuid.UUID]struct{}
}

// NewConn creates a new Conn for the given WebSocket and user.
func NewConn(ws *websocket.Conn, userID uuid.UUID, email string, tenantRole auth.Role, disconnect context.CancelFunc, logger *zap.Logger) *Conn {
	if disconnect == nil {
		panic("realtime: nil connection disconnect")
	}
	id := uuid.New().String()
	return &Conn{
		ID:         id,
		UserID:     userID,
		Email:      email,
		TenantRole: tenantRole,
		ws:         ws,
		send:       make(chan []byte, sendBufferSize),
		disconnect: disconnect,
		jobAgents:  make(map[uuid.UUID]struct{}),
		logger: logger.With(
			zap.String("conn", id),
			zap.String("uid", userID.String()),
			zap.String("email", email),
		),
	}
}

// TrackJobsSubscription records an authorized dynamic jobs subscription.
func (c *Conn) TrackJobsSubscription(agentID uuid.UUID) {
	c.jobsMu.Lock()
	defer c.jobsMu.Unlock()
	if c.jobAgents == nil {
		c.jobAgents = make(map[uuid.UUID]struct{})
	}
	c.jobAgents[agentID] = struct{}{}
}

// UntrackJobsSubscription removes a dynamic jobs subscription.
func (c *Conn) UntrackJobsSubscription(agentID uuid.UUID) {
	c.jobsMu.Lock()
	defer c.jobsMu.Unlock()
	delete(c.jobAgents, agentID)
}

// JobsSubscriptions returns a snapshot of dynamically subscribed agent IDs.
func (c *Conn) JobsSubscriptions() []uuid.UUID {
	c.jobsMu.RLock()
	defer c.jobsMu.RUnlock()
	agentIDs := make([]uuid.UUID, 0, len(c.jobAgents))
	for agentID := range c.jobAgents {
		agentIDs = append(agentIDs, agentID)
	}
	return agentIDs
}

// Send enqueues a message without blocking. Disconnect on overflow: dropping a
// delta while accepting a later sequence would make the loss unreplayable.
func (c *Conn) Send(data []byte) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.overflowed {
		return
	}
	select {
	case c.send <- data:
	default:
		c.overflowed = true
		c.logger.Warn("send buffer full, disconnecting")
		c.disconnect()
	}
}

// SendEnvelope marshals and enqueues an envelope.
func (c *Conn) SendEnvelope(env Envelope) {
	data, err := json.Marshal(env)
	if err != nil {
		return
	}
	c.Send(data)
}

// ReadPump reads messages from the WebSocket and dispatches to handler.
// Blocks until the connection closes or ctx is cancelled.
func (c *Conn) ReadPump(ctx context.Context, handler MessageHandler) {
	defer func() {
		c.ws.Close(websocket.StatusNormalClosure, "")
	}()

	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			return // connection closed or error
		}

		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			c.logger.Warn("invalid message", zap.Error(err))
			continue
		}

		handler(c, env)
	}
}

// WritePump drains the send channel and writes to the WebSocket.
// Also sends periodic pings for liveness detection.
// Blocks until ctx is cancelled or the WebSocket closes.
func (c *Conn) WritePump(ctx context.Context) {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		c.ws.Close(websocket.StatusNormalClosure, "")
	}()

	for {
		select {
		case msg := <-c.send:
			writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := c.ws.Write(writeCtx, websocket.MessageText, msg)
			cancel()
			if err != nil {
				return
			}
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := c.ws.Ping(pingCtx)
			cancel()
			if err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
