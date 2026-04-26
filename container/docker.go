package container

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/config"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/image"
	dcontainer "github.com/docker/docker/api/types/container"
	dmount "github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DockerManager implements ContainerManager using the Docker API.
type DockerManager struct {
	client       *dockerclient.Client
	cfg          *config.Config
	logger       *zap.Logger
	mu           sync.Mutex
	active       map[string]*Container // container name → Container
	lastActivity map[string]time.Time  // container name → last use
	idleTimeout  time.Duration
	stopOnce     sync.Once
	done         chan struct{}
}

// NewDockerManager creates a Docker-based ContainerManager.
func NewDockerManager(cfg *config.Config, logger *zap.Logger) *DockerManager {
	cli, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		panic(fmt.Sprintf("docker: failed to create client: %v", err))
	}

	m := &DockerManager{
		client:       cli,
		cfg:          cfg,
		logger:       logger,
		active:       make(map[string]*Container),
		lastActivity: make(map[string]time.Time),
		idleTimeout:  10 * time.Minute,
		done:         make(chan struct{}),
	}

	go m.reapIdleContainers()
	m.cleanupOrphanedBuilderContainers()

	return m
}

// cleanupOrphanedBuilderContainers removes any leftover airlock-agent-builder-*
// containers from a previous Airlock process that was killed before cleanup.
func (m *DockerManager) cleanupOrphanedBuilderContainers() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	containers, err := m.client.ContainerList(ctx, dcontainer.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("name", "airlock-agent-builder-")),
	})
	if err != nil {
		m.logger.Warn("failed to list orphaned agent-builder containers", zap.Error(err))
		return
	}
	for _, c := range containers {
		m.logger.Info("removing orphaned agent-builder container", zap.String("id", c.ID[:12]), zap.String("state", c.State))
		m.client.ContainerRemove(ctx, c.ID, dcontainer.RemoveOptions{Force: true})
	}
}

// PruneAgentResources removes Docker containers and images for agents that
// no longer exist in the database, and removes stale image tags for active
// agents (keeping only the current image_ref).
//
// validAgents maps agent UUID string → current image_ref (e.g., "uuid:hash").
// Any airlock-agent-* container or UUID-tagged image not matching this set is removed.
func (m *DockerManager) PruneAgentResources(ctx context.Context, validAgents map[string]string) {
	// Build a lookup from container name prefix (first 8 chars of UUID) → full UUID.
	prefixToID := make(map[string]string, len(validAgents))
	for id := range validAgents {
		if len(id) >= 8 {
			prefixToID[id[:8]] = id
		}
	}

	// --- Containers ---
	containers, err := m.client.ContainerList(ctx, dcontainer.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("name", "airlock-agent-")),
	})
	if err != nil {
		m.logger.Warn("prune: failed to list containers", zap.Error(err))
	} else {
		for _, c := range containers {
			// Container names are "/airlock-agent-{first8}"
			name := ""
			for _, n := range c.Names {
				if len(n) > 1 {
					name = n[1:] // strip leading "/"
					break
				}
			}
			prefix := ""
			if len(name) > len("airlock-agent-") {
				prefix = name[len("airlock-agent-"):]
			}
			if _, ok := prefixToID[prefix]; !ok {
				m.logger.Info("prune: removing orphaned container",
					zap.String("name", name), zap.String("state", c.State))
				timeout := 5
				m.client.ContainerStop(ctx, c.ID, dcontainer.StopOptions{Timeout: &timeout})
				m.client.ContainerRemove(ctx, c.ID, dcontainer.RemoveOptions{Force: true})
			}
		}
	}

	// --- Images ---
	// Agent images are tagged as "{agentUUID}:{commitHash}".
	images, err := m.client.ImageList(ctx, image.ListOptions{})
	if err != nil {
		m.logger.Warn("prune: failed to list images", zap.Error(err))
		return
	}

	for _, img := range images {
		for _, tag := range img.RepoTags {
			// Only look at UUID-formatted repo names (agent images).
			if len(tag) < 36 || tag[8] != '-' {
				continue
			}
			agentID := tag[:36] // "uuid" part of "uuid:hash"
			currentRef, exists := validAgents[agentID]
			if !exists {
				// Agent deleted — remove image entirely.
				m.logger.Info("prune: removing image for deleted agent",
					zap.String("image", tag))
				m.client.ImageRemove(ctx, tag, image.RemoveOptions{PruneChildren: true})
			} else if tag != currentRef && currentRef != "" {
				// Stale tag — agent was upgraded, old image still around.
				m.logger.Info("prune: removing stale image tag",
					zap.String("image", tag), zap.String("current", currentRef))
				m.client.ImageRemove(ctx, tag, image.RemoveOptions{PruneChildren: true})
			}
		}
	}
}

// Close stops the idle reaper and closes the Docker client.
func (m *DockerManager) Close() {
	m.stopOnce.Do(func() { close(m.done) })
	m.client.Close()
}

func agentName(agentID uuid.UUID) string {
	return "airlock-agent-" + agentID.String()[:8]
}

// StartAgent implements ContainerManager.
func (m *DockerManager) StartAgent(ctx context.Context, opts AgentOpts) (*Container, error) {
	name := agentName(opts.AgentID)

	m.mu.Lock()
	if c, ok := m.active[name]; ok {
		m.lastActivity[name] = time.Now()
		m.mu.Unlock()
		if err := m.waitHealthy(ctx, c, 3*time.Second); err == nil {
			return c, nil
		}
		m.mu.Lock()
		delete(m.active, name)
		m.mu.Unlock()
	} else {
		m.mu.Unlock()
	}

	if c, err := m.inspectExisting(ctx, name); err == nil {
		if err := m.waitHealthy(ctx, c, 15*time.Second); err == nil {
			m.mu.Lock()
			m.active[name] = c
			m.lastActivity[name] = time.Now()
			m.mu.Unlock()
			return c, nil
		}
		if err := m.client.ContainerRemove(ctx, name, dcontainer.RemoveOptions{Force: true}); err != nil {
			m.logger.Warn("failed to remove unhealthy container", zap.String("name", name), zap.Error(err))
		}
	}

	token, err := auth.IssueAgentToken(m.cfg.JWTSecret, opts.AgentID)
	if err != nil {
		return nil, fmt.Errorf("issue agent token: %w", err)
	}

	image := opts.Image
	if image == "" {
		image = m.cfg.ContainerImage
	}

	env := []string{
		"AIRLOCK_AGENT_TOKEN=" + token,
	}
	for k, v := range opts.Env {
		env = append(env, k+"="+v)
	}

	containerCfg := &dcontainer.Config{
		Image: image,
		Env:   env,
		ExposedPorts: nat.PortSet{
			"8080/tcp": struct{}{},
		},
	}

	hostCfg := &dcontainer.HostConfig{
		ExtraHosts: []string{"host.docker.internal:host-gateway"},
	}

	c, err := m.createAndStart(ctx, name, containerCfg, hostCfg)
	if err != nil {
		return nil, fmt.Errorf("start agent: %w", err)
	}
	c.Token = token

	m.mu.Lock()
	m.active[name] = c
	m.lastActivity[name] = time.Now()
	m.mu.Unlock()

	if err := m.waitHealthy(ctx, c, 15*time.Second); err != nil {
		return nil, fmt.Errorf("agent health check: %w", err)
	}

	return c, nil
}

// GetRunning implements ContainerManager. Returns (nil, nil) when no
// container exists for the agent — caller is expected to treat that as
// "nothing to do" rather than an error. Repopulates the in-memory cache
// when it finds a running container Airlock didn't previously know about
// (typical after an Airlock restart).
func (m *DockerManager) GetRunning(ctx context.Context, agentID uuid.UUID) (*Container, error) {
	name := agentName(agentID)

	m.mu.Lock()
	if c, ok := m.active[name]; ok {
		m.mu.Unlock()
		return c, nil
	}
	m.mu.Unlock()

	c, err := m.inspectExisting(ctx, name)
	if err != nil {
		// Container not found OR exists-but-not-running → nothing to refresh.
		// Distinguishing "not running" from "Docker error" isn't worth a
		// dedicated error type here; the caller logs and moves on either way.
		return nil, nil
	}

	m.mu.Lock()
	m.active[name] = c
	m.lastActivity[name] = time.Now()
	m.mu.Unlock()
	return c, nil
}

// StopAgent implements ContainerManager.
func (m *DockerManager) StopAgent(ctx context.Context, id string) error {
	timeout := 5
	err := m.client.ContainerStop(ctx, id, dcontainer.StopOptions{Timeout: &timeout})
	if err != nil {
		return err
	}
	m.client.ContainerRemove(ctx, id, dcontainer.RemoveOptions{})

	m.mu.Lock()
	for name, c := range m.active {
		if c.ID == id {
			delete(m.active, name)
			delete(m.lastActivity, name)
			break
		}
	}
	m.mu.Unlock()

	return nil
}

// RemoveImage removes a Docker image by reference.
func (m *DockerManager) RemoveImage(ctx context.Context, imageRef string) error {
	_, err := m.client.ImageRemove(ctx, imageRef, image.RemoveOptions{PruneChildren: true})
	return err
}

// StartToolserver starts an ephemeral toolserver container for build operations.
// The container runs the toolserver binary with the workspace mounted.
// Returns the container with a WebSocket endpoint for remote tool execution.
func (m *DockerManager) StartToolserver(ctx context.Context, opts ToolserverOpts) (*Container, error) {
	name := fmt.Sprintf("airlock-agent-builder-%d", time.Now().UnixNano())

	cmd := []string{"toolserver", "-space-dir", opts.WorkDir}

	// Run as the host UID/GID so files written to the bind-mounted workspace
	// are owned by the same user, preventing permission errors on git operations.
	uid := os.Getuid()
	gid := os.Getgid()

	// Set Go env vars to writable locations since we run as non-root UID.
	env := append(opts.Env,
		"GOCACHE=/tmp/go-cache",
		"GOMODCACHE=/tmp/go-mod",
		"GONOSUMDB=*",
		"GOFLAGS=-buildvcs=false",
	)

	containerCfg := &dcontainer.Config{
		Image: opts.Image,
		Env:   env,
		Cmd:   cmd,
		User:  fmt.Sprintf("%d:%d", uid, gid),
		ExposedPorts: nat.PortSet{
			"8080/tcp": struct{}{},
		},
	}

	// Persistent volume for Go module + build caches across codegen runs.
	mounts := append(opts.Mounts,
		dmount.Mount{Type: dmount.TypeVolume, Source: "airlock-go-mod-cache", Target: "/tmp/go-mod"},
		dmount.Mount{Type: dmount.TypeVolume, Source: "airlock-go-build-cache", Target: "/tmp/go-cache"},
	)

	hostCfg := &dcontainer.HostConfig{
		Mounts: mounts,
	}

	c, err := m.createAndStart(ctx, name, containerCfg, hostCfg)
	if err != nil {
		return nil, fmt.Errorf("start toolserver: %w", err)
	}

	if err := m.waitHealthy(ctx, c, 15*time.Second); err != nil {
		m.client.ContainerRemove(context.Background(), c.ID, dcontainer.RemoveOptions{Force: true})
		return nil, fmt.Errorf("toolserver health check: %w", err)
	}

	m.logger.Info("toolserver started", zap.String("container", name), zap.String("endpoint", c.Endpoint))
	return c, nil
}

// StopToolserver stops and removes an ephemeral toolserver container.
func (m *DockerManager) StopToolserver(ctx context.Context, name string) error {
	timeout := 5
	if err := m.client.ContainerStop(ctx, name, dcontainer.StopOptions{Timeout: &timeout}); err != nil {
		m.logger.Warn("failed to stop toolserver", zap.String("name", name), zap.Error(err))
	}
	return m.client.ContainerRemove(ctx, name, dcontainer.RemoveOptions{Force: true})
}

func (m *DockerManager) createAndStart(ctx context.Context, name string, cfg *dcontainer.Config, hostCfg *dcontainer.HostConfig) (*Container, error) {
	if err := m.client.ContainerRemove(ctx, name, dcontainer.RemoveOptions{Force: true}); err != nil && !cerrdefs.IsNotFound(err) {
		m.logger.Warn("failed to remove existing container", zap.String("name", name), zap.Error(err))
	}

	netCfg := &network.NetworkingConfig{}
	if m.cfg.DockerNetwork != "" {
		netCfg.EndpointsConfig = map[string]*network.EndpointSettings{
			m.cfg.DockerNetwork: {},
		}
	}

	resp, err := m.client.ContainerCreate(ctx, cfg, hostCfg, netCfg, nil, name)
	if err != nil {
		return nil, fmt.Errorf("create container %s: %w", name, err)
	}

	if err := m.client.ContainerStart(ctx, resp.ID, dcontainer.StartOptions{}); err != nil {
		return nil, fmt.Errorf("start container %s: %w", name, err)
	}

	endpoint, err := m.getEndpoint(ctx, resp.ID)
	if err != nil {
		return nil, err
	}

	return &Container{
		ID:       resp.ID,
		Name:     name,
		Endpoint: endpoint,
	}, nil
}

func (m *DockerManager) inspectExisting(ctx context.Context, name string) (*Container, error) {
	info, err := m.client.ContainerInspect(ctx, name)
	if err != nil {
		return nil, err
	}
	if !info.State.Running {
		return nil, fmt.Errorf("container %s exists but not running", name)
	}

	endpoint, err := m.getEndpoint(ctx, info.ID)
	if err != nil {
		return nil, err
	}

	return &Container{
		ID:       info.ID,
		Name:     name,
		Endpoint: endpoint,
	}, nil
}

func (m *DockerManager) getEndpoint(ctx context.Context, containerID string) (string, error) {
	info, err := m.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return "", fmt.Errorf("inspect container: %w", err)
	}

	for _, nw := range info.NetworkSettings.Networks {
		if nw.IPAddress != "" {
			return fmt.Sprintf("http://%s:8080", nw.IPAddress), nil
		}
	}

	return "", fmt.Errorf("no IP address found for container %s", containerID)
}

func (m *DockerManager) waitHealthy(ctx context.Context, c *Container, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		resp, err := httpGet(c.Endpoint + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}

		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("container %s did not become healthy within %v", c.Name, timeout)
}

func (m *DockerManager) reapIdleContainers() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			var toStop []struct {
				name string
				id   string
			}
			for name, lastUse := range m.lastActivity {
				if now.Sub(lastUse) > m.idleTimeout {
					if c, ok := m.active[name]; ok {
						toStop = append(toStop, struct {
							name string
							id   string
						}{name, c.ID})
					}
				}
			}
			for _, s := range toStop {
				delete(m.active, s.name)
				delete(m.lastActivity, s.name)
			}
			m.mu.Unlock()

			for _, s := range toStop {
				m.logger.Info("stopping idle container", zap.String("name", s.name))
				ctx := context.Background()
				timeout := 5
				m.client.ContainerStop(ctx, s.id, dcontainer.StopOptions{Timeout: &timeout})
				m.client.ContainerRemove(ctx, s.id, dcontainer.RemoveOptions{})
			}
		}
	}
}
