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

	// StopAgent stops a specific agent container.
	StopAgent(ctx context.Context, id string) error

	// StartToolserver starts an ephemeral toolserver container for build operations.
	// Returns the container with a WebSocket endpoint for tool execution.
	StartToolserver(ctx context.Context, opts ToolserverOpts) (*Container, error)

	// StopToolserver stops and removes an ephemeral toolserver container.
	StopToolserver(ctx context.Context, name string) error

	// RemoveImage removes a Docker image by reference (e.g., "agentID:hash").
	RemoveImage(ctx context.Context, imageRef string) error
}
