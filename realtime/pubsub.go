package realtime

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PubSub delivers real-time envelopes to local WebSocket subscribers via the Hub.
// This is the single-instance implementation. For multi-instance fan-out (e.g.
// via Redis pub/sub), replace or extend this with a cross-process transport.
type PubSub struct {
	hub    *Hub
	logger *zap.Logger
}

// NewPubSub creates a PubSub wired to the given Hub.
func NewPubSub(hub *Hub, logger *zap.Logger) *PubSub {
	return &PubSub{
		hub:    hub,
		logger: logger,
	}
}

// Publish delivers an envelope to all local subscribers of the topic.
func (ps *PubSub) Publish(ctx context.Context, topicID uuid.UUID, env Envelope) error {
	ps.hub.BroadcastToTopic(topicID, env)
	return nil
}

// ClearTopicBuffer removes the replay buffer for a topic.
// Call after terminal events (run complete, build complete) so reconnecting
// clients don't replay stale streaming events.
func (ps *PubSub) ClearTopicBuffer(topicID uuid.UUID) {
	ps.hub.ClearTopicBuffer(topicID)
}

// Close is a no-op for the local implementation.
func (ps *PubSub) Close() {}
