package realtime

import (
	"context"
	"encoding/json"
	"time"

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
	ws     *websocket.Conn
	send   chan []byte
	logger *zap.Logger
}

// NewConn creates a new Conn for the given WebSocket and user.
func NewConn(ws *websocket.Conn, userID uuid.UUID, email string, logger *zap.Logger) *Conn {
	id := uuid.New().String()
	return &Conn{
		ID:     id,
		UserID: userID,
		Email:  email,
		ws:     ws,
		send:   make(chan []byte, sendBufferSize),
		logger: logger.With(
			zap.String("conn", id),
			zap.String("uid", userID.String()),
			zap.String("email", email),
		),
	}
}

// Send enqueues a message for writing. Non-blocking: drops if buffer full.
func (c *Conn) Send(data []byte) {
	select {
	case c.send <- data:
	default:
		c.logger.Warn("send buffer full, dropping message")
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
// Blocks until the send channel is closed or ctx is cancelled.
func (c *Conn) WritePump(ctx context.Context) {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		c.ws.Close(websocket.StatusNormalClosure, "")
	}()

	for {
		select {
		case msg, ok := <-c.send:
			if !ok {
				return // channel closed
			}
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

// Close closes the send channel, causing WritePump to exit.
func (c *Conn) Close() {
	close(c.send)
}
