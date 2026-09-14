package realtime

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PubSub delivers envelopes through its explicitly selected transport.
type PubSub struct {
	hub    *Hub
	shared *sharedPubSub
}

// NewPubSub creates a PubSub wired to the given Hub.
func NewPubSub(hub *Hub, logger *zap.Logger) *PubSub {
	if hub == nil || logger == nil {
		panic("realtime: nil pubsub dependency")
	}
	return &PubSub{
		hub: hub,
	}
}

// Publish commits an envelope before shared delivery, or delivers locally for NewPubSub.
func (ps *PubSub) Publish(ctx context.Context, topicID uuid.UUID, env Envelope) error {
	if ps.shared != nil {
		return ps.shared.publish(ctx, topicID, env)
	}
	ps.hub.BroadcastToTopic(topicID, env)
	return nil
}

// ClearTopicBuffer removes the replay buffer for a topic.
// Call after terminal events (run complete, build complete) so reconnecting
// clients don't replay stale streaming events.
func (ps *PubSub) ClearTopicBuffer(topicID uuid.UUID) {
	ps.hub.ClearTopicBuffer(topicID)
}

// Close is a no-op; Run is stopped by its context and the caller owns the pool.
func (ps *PubSub) Close() {}
