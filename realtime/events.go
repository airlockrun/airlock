package realtime

import (
	"context"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
)

// BuildEventPublisher adapts PubSub to the builder.EventPublisher interface.
//
// Build events split across two topics: lightweight lifecycle status
// (agent.build, carrying tasks_done/total for the badge) broadcasts on the
// AGENT topic so every member's UI updates without opening the Build page;
// the verbose stream (log lines, live actions, todos) publishes on the
// per-BUILD topic, which the Build page subscribes to only while open.
type BuildEventPublisher struct {
	pubsub *PubSub
	hub    *Hub
}

// NewBuildEventPublisher creates a BuildEventPublisher.
func NewBuildEventPublisher(ps *PubSub, hub *Hub) *BuildEventPublisher {
	return &BuildEventPublisher{pubsub: ps, hub: hub}
}

// PublishBuildEvent publishes an agent build lifecycle event on the agent
// topic. tasksDone/tasksTotal drive the "Building N/M tasks" badge.
func (p *BuildEventPublisher) PublishBuildEvent(ctx context.Context, agentID, buildID uuid.UUID, status, errMsg, phase string, tasksDone, tasksTotal int32) {
	env := NewEnvelope("agent.build", agentID.String(), &airlockv1.AgentBuildEvent{
		AgentId:    agentID.String(),
		BuildId:    buildID.String(),
		Status:     status,
		Error:      errMsg,
		TasksDone:  tasksDone,
		TasksTotal: tasksTotal,
		Phase:      phase,
	})
	_ = p.pubsub.Publish(ctx, agentID, env)

	// Clear replay buffers on terminal events — no need to replay a finished
	// build to a late subscriber (the REST snapshot is authoritative).
	if status == "complete" || status == "failed" || status == "cancelled" {
		p.hub.ClearTopicBuffer(agentID)
		p.hub.ClearTopicBuffer(buildID)
	}
}

// PublishBuildLogLine publishes a single build log line on the per-build topic.
// seq is a monotonic counter per build (across both sol and docker streams);
// the frontend uses it to dedupe against a REST snapshot of the persisted log.
func (p *BuildEventPublisher) PublishBuildLogLine(ctx context.Context, agentID, buildID uuid.UUID, seq int64, stream, line string) {
	env := NewEnvelope("agent.build.log", buildID.String(), &airlockv1.AgentBuildLogEvent{
		AgentId: agentID.String(),
		BuildId: buildID.String(),
		Seq:     seq,
		Stream:  stream,
		Line:    line,
	})
	_ = p.pubsub.Publish(ctx, buildID, env)
}

// PublishBuildAction publishes one compact tool action on the per-build topic
// (the Build page's "Live actions" feed).
func (p *BuildEventPublisher) PublishBuildAction(ctx context.Context, buildID uuid.UUID, seq int64, kind, label, detail, toolCallID, toolName string) {
	env := NewEnvelope("agent.build.action", buildID.String(), &airlockv1.AgentBuildActionEvent{
		BuildId:    buildID.String(),
		Seq:        seq,
		Kind:       kind,
		Label:      label,
		Detail:     detail,
		ToolCallId: toolCallID,
		ToolName:   toolName,
	})
	_ = p.pubsub.Publish(ctx, buildID, env)
}

// PublishBuildTodos publishes the agent's full todo list on the per-build
// topic. todosJSON is the same jsonb blob persisted to agent_builds.todos.
func (p *BuildEventPublisher) PublishBuildTodos(ctx context.Context, buildID uuid.UUID, seq int64, todosJSON []byte) {
	env := NewEnvelope("agent.build.todos", buildID.String(), &airlockv1.AgentBuildTodoEvent{
		BuildId: buildID.String(),
		Seq:     seq,
		Todos:   convert.TodosFromJSON(todosJSON),
	})
	_ = p.pubsub.Publish(ctx, buildID, env)
}
