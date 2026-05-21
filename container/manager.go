// Package container provides container lifecycle management for agents.
package container

import (
	"context"

	"github.com/docker/docker/api/types/mount"
	"github.com/google/uuid"
)

// Container represents a running container.
type Container struct {
	ID       string // Docker container ID
	Name     string // Human-readable name
	Endpoint string // HTTP endpoint (e.g., "http://172.17.0.2:8080")
	Token    string // Bearer token for authenticating requests to this container
}

// AgentOpts configures an agent container.
type AgentOpts struct {
	AgentID uuid.UUID
	Image   string            // Docker image to run (e.g., "my-agent:abc123")
	Env     map[string]string // Additional environment variables
}

// ToolserverOpts configures an ephemeral toolserver container for build operations.
type ToolserverOpts struct {
	Image   string        // toolserver image (e.g., "agent-builder:v1.0.0")
	Mounts  []mount.Mount // workspace bind mounts
	WorkDir string        // -space-dir value inside the container
	Env     []string      // additional environment variables
}

// ContainerManager manages the lifecycle of agent containers.
type ContainerManager interface {
	// StartAgent ensures an agent container is running.
	// Returns the existing container if already running and healthy.
	StartAgent(ctx context.Context, opts AgentOpts) (*Container, error)

	// GetRunning returns the running container for an agent without starting
	// one if absent. Returns (nil, nil) when no container is up. Used by
	// out-of-band signals (e.g. /refresh push) where booting a container
	// just to notify it would defeat the purpose.
	GetRunning(ctx context.Context, agentID uuid.UUID) (*Container, error)

	// RunningAgents reports, per requested agent ID, whether a running
	// container currently exists for it. One Docker query regardless of
	// how many agents are asked about — for list/grid views that would
	// otherwise fan out into one inspect per agent.
	RunningAgents(ctx context.Context, agentIDs []uuid.UUID) (map[uuid.UUID]bool, error)

	// StopAgent stops a specific agent container.
	StopAgent(ctx context.Context, id string) error

	// MarkBusy / MarkIdle bracket an in-flight request to an agent
	// container. While the in-flight count is above zero the idle
	// reaper leaves the container alone, even past the idle timeout —
	// so a run that runs longer than the timeout is not killed
	// mid-execution. MarkIdle also refreshes the idle clock, so the
	// timeout is measured from the end of the last request. Pair every
	// MarkBusy with exactly one MarkIdle.
	MarkBusy(agentID uuid.UUID)
	MarkIdle(agentID uuid.UUID)

	// StartToolserver starts an ephemeral toolserver container for build operations.
	// Returns the container with a WebSocket endpoint for tool execution.
	StartToolserver(ctx context.Context, opts ToolserverOpts) (*Container, error)

	// StopToolserver stops and removes an ephemeral toolserver container.
	StopToolserver(ctx context.Context, name string) error

	// KillToolserver force-kills (SIGKILL) and removes an ephemeral
	// toolserver container without waiting for graceful shutdown. Used
	// on the build-cancel path so an in-flight tool stops emitting logs
	// the moment cancel hits, instead of after the 5s graceful timeout.
	KillToolserver(ctx context.Context, name string) error

	// RemoveImage removes a Docker image by reference (e.g., "agentID:hash").
	RemoveImage(ctx context.Context, imageRef string) error
}
