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
	// Image is the tag the container was started with, copied from
	// Docker's Config.Image at inspect time. StartAgent compares this
	// against opts.Image to detect a stale running container after a
	// build/rollback swap — adopting one with the wrong image would
	// silently keep the agent on the old code.
	Image string
}

// AgentOpts configures an agent container.
type AgentOpts struct {
	AgentID uuid.UUID
	Image   string            // Docker image to run (e.g., "my-agent:abc123")
	Env     map[string]string // Additional environment variables
}

// ToolserverOpts configures an ephemeral toolserver container for build operations.
type ToolserverOpts struct {
	Image       string        // toolserver image (e.g., "agent-builder:v1.0.0")
	Mounts      []mount.Mount // workspace bind mounts
	WorkDir     string        // -space-dir value inside the container
	Env         []string      // additional environment variables
	LogCallback func(line string)
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

	// StopAgent stops a specific agent's container (resolved from the agent
	// ID via the instance-scoped name scheme).
	StopAgent(ctx context.Context, agentID uuid.UUID) error

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

	// CaptureToolserverDiagnostics snapshots abnormal runtime state/logs
	// before the ephemeral toolserver container is removed.
	CaptureToolserverDiagnostics(ctx context.Context, name, reason string) error

	// RemoveImage removes a Docker image by reference (e.g., "agentID:hash").
	RemoveImage(ctx context.Context, imageRef string) error

	// LockSwap serializes the agent's container-swap window. Held by the
	// builder around Phase F (StopAgent → StartAgent → UpdateAgentRefs)
	// and by EnsureRunning around its GetAgent → StartAgent critical
	// section, so a concurrent trigger can't start the old image while a
	// build is mid-swap (and vice versa). Returns a release function
	// callers must defer. Scope is just the swap — codegen, image build,
	// and migration validation all run outside the lock.
	LockSwap(agentID uuid.UUID) func()
}
