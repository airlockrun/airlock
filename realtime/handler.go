package realtime

import (
	"github.com/airlockrun/airlock/db"
	"go.uber.org/zap"
)

// Handler routes inbound WebSocket messages. Subscriptions are no longer
// client-initiated — the WS upgrade handler auto-subscribes new connections
// to every agent the user is a member of, based on durable agent_members
// state. Any inbound message from the client is therefore unexpected; we
// log and reject so misbehaving clients don't silently drift.
type Handler struct {
	db     *db.DB
	hub    *Hub
	pubsub *PubSub
	logger *zap.Logger
}

// NewHandler creates a new inbound message handler.
func NewHandler(database *db.DB, hub *Hub, pubsub *PubSub, logger *zap.Logger) *Handler {
	return &Handler{
		db:     database,
		hub:    hub,
		pubsub: pubsub,
		logger: logger,
	}
}

// HandleMessage rejects all inbound messages. The WS is server→client only.
func (h *Handler) HandleMessage(conn *Conn, env Envelope) {
	conn.logger.Info("ws recv (rejected)", zap.String("type", env.Type))
	conn.SendEnvelope(errorEnvelope(env.RequestID, "unexpected message type: "+env.Type))
}
