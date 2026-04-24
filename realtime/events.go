package realtime

import (
	"context"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
)

// BuildEventPublisher adapts PubSub to the builder.EventPublisher interface.
type BuildEventPublisher struct {
	pubsub *PubSub
	hub    *Hub
}

// NewBuildEventPublisher creates a BuildEventPublisher.
func NewBuildEventPublisher(ps *PubSub, hub *Hub) *BuildEventPublisher {
	return &BuildEventPublisher{pubsub: ps, hub: hub}
}

// PublishBuildEvent publishes an agent build lifecycle event.
func (p *BuildEventPublisher) PublishBuildEvent(ctx context.Context, agentID, buildID uuid.UUID, status, errMsg string) {
	env := NewEnvelope("agent.build", agentID.String(), &airlockv1.AgentBuildEvent{
		AgentId: agentID.String(),
		BuildId: buildID.String(),
		Status:  status,
		Error:   errMsg,
	})
	_ = p.pubsub.Publish(ctx, agentID, env)

	// Clear replay buffer on terminal events — no need to replay a finished build.
	if status == "complete" || status == "failed" || status == "cancelled" {
		p.hub.ClearTopicBuffer(agentID)
	}
}

// PublishBuildLogLine publishes a single build log line for real-time streaming.
// seq is a monotonic counter per build (across both sol and docker streams); the
// frontend uses it to dedupe against a REST snapshot of the persisted log.
func (p *BuildEventPublisher) PublishBuildLogLine(ctx context.Context, agentID, buildID uuid.UUID, seq int64, stream, line string) {
	env := NewEnvelope("agent.build.log", agentID.String(), &airlockv1.AgentBuildLogEvent{
		AgentId: agentID.String(),
		BuildId: buildID.String(),
		Seq:     seq,
		Stream:  stream,
		Line:    line,
	})
	_ = p.pubsub.Publish(ctx, agentID, env)
}
