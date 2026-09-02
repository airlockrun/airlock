package container

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/config"
	cerrdefs "github.com/containerd/errdefs"
	dcontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	dmount "github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// AgentStartupHealthTimeout bounds cold runtime initialization, including
// migrations and process-local startup hooks that complete before readiness.
const AgentStartupHealthTimeout = 2 * time.Minute

// DockerManager implements ContainerManager using the Docker API.
type DockerManager struct {
	client                 *dockerclient.Client
	cfg                    *config.Config
	logger                 *zap.Logger
	pool                   *pgxpool.Pool
	networkPolicy          RuntimeNetworkPolicy
	mu                     sync.Mutex
	active                 map[string]*Container // container name → Container
	lastActivity           map[string]time.Time  // container name → last use
	inFlight               map[string]int        // container name → in-flight request count
	toolserverLogCallbacks map[string]func(string)
	toolserverDiagCaptured map[string]bool
	idleTimeout            time.Duration
	stopOnce               sync.Once
	done                   chan struct{}
	// swapMu serializes the per-agent container-swap critical section
	// (see LockSwap). One *sync.Mutex per agent ID, lazily created.
	swapMu sync.Map // agentID(string) → *sync.Mutex
}

// NewDockerManager creates a Docker-based ContainerManager.
func NewDockerManager(cfg *config.Config, pool *pgxpool.Pool, networkPolicy RuntimeNetworkPolicy, logger *zap.Logger) *DockerManager {
	if pool == nil {
		panic("container: database pool is required")
	}
	if networkPolicy == nil {
		panic("container: runtime network policy is required")
	}
	cli, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		panic(fmt.Sprintf("docker: failed to create client: %v", err))
	}

	m := &DockerManager{
		client:                 cli,
		cfg:                    cfg,
		logger:                 logger,
		pool:                   pool,
		networkPolicy:          networkPolicy,
		active:                 make(map[string]*Container),
		lastActivity:           make(map[string]time.Time),
		inFlight:               make(map[string]int),
		toolserverLogCallbacks: make(map[string]func(string)),
		toolserverDiagCaptured: make(map[string]bool),
		idleTimeout:            10 * time.Minute,
		done:                   make(chan struct{}),
	}

	go m.reapIdleContainers()
	m.cleanupOrphanedBuilderContainers()

	return m
}

// cleanupOrphanedBuilderContainers removes any leftover <instance>-agent-builder-*
// containers from a previous Airlock process that was killed before cleanup.
// Scoped to this instance via the ownership label.
func (m *DockerManager) cleanupOrphanedBuilderContainers() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := m.instanceFilter()
	f.Add("name", m.builderPrefix())
	containers, err := m.client.ContainerList(ctx, dcontainer.ListOptions{
		All:     true,
		Filters: f,
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
// AgentRuntimeSpec is the persisted identity a reusable agent container must
// match.
type AgentRuntimeSpec struct {
	Image        string
	TokenVersion int64
	Status       string
}

// validAgents maps agent UUID string to its current runtime identity.
// Any container or UUID-tagged image owned by this instance (run.airlock.instance
// label) not matching this set is removed. Other instances' resources carry a
// different label value and are never listed here.
func (m *DockerManager) PruneAgentResources(ctx context.Context, validAgents map[string]AgentRuntimeSpec) []uuid.UUID {
	var recreate []uuid.UUID
	// Build a lookup from container name prefix (first 8 chars of UUID) → full UUID.
	prefixToID := make(map[string]string, len(validAgents))
	for id := range validAgents {
		if len(id) >= 8 {
			prefixToID[id[:8]] = id
		}
	}

	agentPrefix := m.agentPrefix()

	// --- Containers ---
	containers, err := m.client.ContainerList(ctx, dcontainer.ListOptions{
		All:     true,
		Filters: m.instanceFilter(),
	})
	if err != nil {
		m.logger.Warn("prune: failed to list containers", zap.Error(err))
	} else {
		for _, c := range containers {
			// Container names are "/<instance>-agent-{first8}"
			name := ""
			for _, n := range c.Names {
				if len(n) > 1 {
					name = n[1:] // strip leading "/"
					break
				}
			}
			prefix := ""
			if len(name) > len(agentPrefix) {
				prefix = name[len(agentPrefix):]
			}
			agentID, ok := prefixToID[prefix]
			if !ok {
				m.logger.Info("prune: removing orphaned container",
					zap.String("name", name), zap.String("state", c.State))
				timeout := 5
				m.client.ContainerStop(ctx, c.ID, dcontainer.StopOptions{Timeout: &timeout})
				m.client.ContainerRemove(ctx, c.ID, dcontainer.RemoveOptions{Force: true})
				continue
			}

			spec := validAgents[agentID]
			desired, issueErr := auth.IssueAgentToken(m.cfg.JWTSecret, uuid.MustParse(agentID), spec.TokenVersion)
			info, inspectErr := m.client.ContainerInspect(ctx, c.ID)
			token := ""
			image := ""
			if inspectErr == nil && info.Config != nil {
				token = agentTokenFromEnv(info.Config.Env)
				image = info.Config.Image
			}
			if issueErr != nil || inspectErr != nil || image != spec.Image || !reusableAgentToken(m.cfg.JWTSecret, token, desired, time.Now()) {
				m.logger.Info("prune: removing stale agent container",
					zap.String("name", name), zap.String("state", c.State))
				m.client.ContainerRemove(ctx, c.ID, dcontainer.RemoveOptions{Force: true})
				if c.State == "running" && spec.Status == "active" {
					recreate = append(recreate, uuid.MustParse(agentID))
				}
			}
		}
	}
	m.pruneAgentNetworks(ctx)

	// --- Images ---
	// Agent images are tagged as "{agentUUID}:{commitHash}" and carry this
	// instance's ownership label (set at build time via --label), so the
	// filter keeps another instance's images out of the prune set.
	images, err := m.client.ImageList(ctx, image.ListOptions{Filters: m.instanceFilter()})
	if err != nil {
		m.logger.Warn("prune: failed to list images", zap.Error(err))
		return recreate
	}

	for _, img := range images {
		for _, tag := range img.RepoTags {
			// Only look at UUID-formatted repo names (agent images).
			if len(tag) < 36 || tag[8] != '-' {
				continue
			}
			agentID := tag[:36] // "uuid" part of "uuid:hash"
			spec, exists := validAgents[agentID]
			if !exists {
				// Agent deleted — remove image entirely.
				m.logger.Info("prune: removing image for deleted agent",
					zap.String("image", tag))
				m.client.ImageRemove(ctx, tag, image.RemoveOptions{PruneChildren: true})
			} else if tag != spec.Image && spec.Image != "" {
				// Stale tag — agent was upgraded, old image still around.
				m.logger.Info("prune: removing stale image tag",
					zap.String("image", tag), zap.String("current", spec.Image))
				m.client.ImageRemove(ctx, tag, image.RemoveOptions{PruneChildren: true})
			}
		}
	}
	return recreate
}

// Close stops the idle reaper and closes the Docker client.
func (m *DockerManager) Close() {
	m.stopOnce.Do(func() { close(m.done) })
	m.client.Close()
}

// labelInstance is the ownership label key (see config.LabelInstance).
// Names carry the same instance prefix only for daemon-global uniqueness
// and readability; the label is what list/prune filter on.
const labelInstance = config.LabelInstance

const (
	labelAgentID           = "run.airlock.agent"
	labelResource          = "run.airlock.resource"
	resourceAgentNet       = "agent-network"
	resourceManifest       = "manifest"
	agentNetworkLockID     = int64(684163872)
	maxManifestBytes       = 4 << 20
	maxManifestStdoutBytes = maxManifestBytes + 1
	maxManifestStderrBytes = 64 << 10
	manifestMemoryBytes    = 256 << 20
	manifestPidsLimit      = int64(256)
	manifestCleanupTimeout = 10 * time.Second
	connectorBuildMemory   = 2 << 30
	connectorBuildPids     = int64(512)
)

// agentPrefix is the instance-scoped name prefix for agent runtime
// containers ("<instance>-agent-"). builderPrefix is the same for
// ephemeral build/toolserver containers ("<instance>-agent-builder-").
func (m *DockerManager) agentPrefix() string   { return m.cfg.InstanceID + "-agent-" }
func (m *DockerManager) builderPrefix() string { return m.cfg.InstanceID + "-agent-builder-" }

// instanceFilter scopes a Docker list call to this instance's resources
// via the ownership label.
func (m *DockerManager) instanceFilter() filters.Args {
	return filters.NewArgs(filters.Arg("label", labelInstance+"="+m.cfg.InstanceID))
}

func (m *DockerManager) agentName(agentID uuid.UUID) string {
	return m.agentPrefix() + agentID.String()[:8]
}

func (m *DockerManager) agentNetworkName(agentID uuid.UUID) string {
	return m.cfg.InstanceID + "-agent-net-" + agentID.String()
}

func (m *DockerManager) agentRuntimeNetworkName(agentID uuid.UUID) string {
	if m.cfg.AgentNetworkPerAgent {
		return m.agentNetworkName(agentID)
	}
	return m.cfg.DockerNetwork
}

// StartAgent implements ContainerManager.
func (m *DockerManager) StartAgent(ctx context.Context, opts AgentOpts) (*Container, error) {
	desiredClaims, err := auth.ValidateAgentToken(m.cfg.JWTSecret, opts.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid agent token for container: %w", err)
	}
	if desiredClaims.AgentID != opts.AgentID.String() {
		return nil, fmt.Errorf("agent token belongs to %s, not %s", desiredClaims.AgentID, opts.AgentID)
	}
	unlock, err := m.lockAgentNetwork(ctx, opts.AgentID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	name := m.agentName(opts.AgentID)
	networkName := m.agentRuntimeNetworkName(opts.AgentID)
	if m.cfg.AgentNetworkPerAgent {
		if err := m.ensureAgentNetwork(ctx, opts.AgentID); err != nil {
			return nil, fmt.Errorf("prepare agent network: %w", err)
		}
	}

	// Stale-image guard: an existing container with the wrong image must
	// be replaced, not adopted. Without this check, a rollback that
	// races with a trigger (the trigger starts the OLD image while the
	// rollback is mid-swap) results in agents.image_ref pointing to the
	// new image while the running container serves the old code. The
	// check runs against both the cache and the live Docker state.
	imageMatch := func(have string) bool {
		return opts.Image == "" || have == "" || have == opts.Image
	}
	runtimeMatch := func(c *Container) bool {
		return imageMatch(c.Image) &&
			(networkName == "" || c.Network == networkName) &&
			reusableAgentToken(m.cfg.JWTSecret, c.Token, opts.Token, time.Now())
	}

	m.mu.Lock()
	if c, ok := m.active[name]; ok && runtimeMatch(c) {
		m.lastActivity[name] = time.Now()
		m.mu.Unlock()
		if err := m.waitHealthy(ctx, c, 3*time.Second); err == nil {
			return c, nil
		}
		m.mu.Lock()
		delete(m.active, name)
		m.mu.Unlock()
	} else {
		// Cache hit with wrong image, or no cache entry: drop the stale
		// entry so it doesn't shadow the freshly-built container below.
		if ok {
			delete(m.active, name)
		}
		m.mu.Unlock()
	}

	if c, err := m.inspectExisting(ctx, name); err == nil {
		if runtimeMatch(c) {
			if err := m.waitHealthy(ctx, c, AgentStartupHealthTimeout); err == nil {
				m.mu.Lock()
				m.active[name] = c
				m.lastActivity[name] = time.Now()
				m.mu.Unlock()
				return c, nil
			}
		} else {
			m.logger.Info("stale agent container, replacing",
				zap.String("name", name),
				zap.String("have", c.Image),
				zap.String("want", opts.Image))
		}
		if err := m.client.ContainerRemove(ctx, name, dcontainer.RemoveOptions{Force: true}); err != nil {
			m.logger.Warn("failed to remove existing container", zap.String("name", name), zap.Error(err))
		}
	}

	image := opts.Image
	if image == "" {
		image = m.cfg.ContainerImage
	}

	env := []string{
		"AIRLOCK_AGENT_TOKEN=" + opts.Token,
	}
	for k, v := range opts.Env {
		if k == "AIRLOCK_AGENT_TOKEN" {
			return nil, fmt.Errorf("AIRLOCK_AGENT_TOKEN must be supplied through AgentOpts.Token")
		}
		env = append(env, k+"="+v)
	}

	containerCfg := &dcontainer.Config{
		Image: image,
		Env:   env,
		Labels: map[string]string{
			labelAgentID: opts.AgentID.String(),
		},
		ExposedPorts: nat.PortSet{
			"8080/tcp": struct{}{},
		},
	}

	hostCfg := buildAgentHostConfig(m.cfg)

	c, err := m.createAndStart(ctx, name, containerCfg, hostCfg, networkName)
	if err != nil {
		if m.cfg.AgentNetworkPerAgent {
			_ = m.cleanupAgentNetwork(ctx, opts.AgentID)
		}
		return nil, fmt.Errorf("start agent: %w", err)
	}
	c.Token = opts.Token
	c.Image = image
	c.AgentID = opts.AgentID

	m.mu.Lock()
	m.active[name] = c
	m.lastActivity[name] = time.Now()
	m.mu.Unlock()

	if err := m.waitHealthy(ctx, c, AgentStartupHealthTimeout); err != nil {
		_ = m.client.ContainerRemove(context.Background(), c.ID, dcontainer.RemoveOptions{Force: true})
		if m.cfg.AgentNetworkPerAgent {
			_ = m.cleanupAgentNetwork(context.Background(), opts.AgentID)
		}
		return nil, fmt.Errorf("agent health check: %w", err)
	}

	return c, nil
}

func reusableAgentToken(secret, existing, desired string, now time.Time) bool {
	existingClaims, err := auth.ValidateAgentToken(secret, existing)
	if err != nil || existingClaims.ExpiresAt == nil || existingClaims.ExpiresAt.Time.Before(now.Add(auth.AgentTokenRotationWindow)) {
		return false
	}
	desiredClaims, err := auth.ValidateAgentToken(secret, desired)
	if err != nil {
		return false
	}
	return existingClaims.AgentID == desiredClaims.AgentID &&
		existingClaims.Profile == desiredClaims.Profile &&
		existingClaims.TokenVersion == desiredClaims.TokenVersion
}

func agentTokenFromEnv(env []string) string {
	for _, value := range env {
		if v, ok := strings.CutPrefix(value, "AIRLOCK_AGENT_TOKEN="); ok {
			return v
		}
	}
	return ""
}

// GetRunning implements ContainerManager. Returns (nil, nil) when no
// container exists for the agent — caller is expected to treat that as
// "nothing to do" rather than an error. Repopulates the in-memory cache
// when it finds a running container Airlock didn't previously know about
// (typical after an Airlock restart).
func (m *DockerManager) GetRunning(ctx context.Context, agentID uuid.UUID) (*Container, error) {
	name := m.agentName(agentID)

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

// RunningAgents implements ContainerManager. One ContainerList call,
// scoped to this instance via the ownership label, then matched back to
// the requested IDs via agentName. Builder/toolserver containers
// ("<instance>-agent-builder-*") also carry the label but never equal an
// agentName(id), so they fall out of the lookup harmlessly.
func (m *DockerManager) RunningAgents(ctx context.Context, agentIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	list, err := m.client.ContainerList(ctx, dcontainer.ListOptions{
		Filters: m.instanceFilter(),
	})
	if err != nil {
		return nil, err
	}
	// ContainerList without All:true returns only running containers.
	running := make(map[string]struct{}, len(list))
	for _, c := range list {
		for _, n := range c.Names {
			running[strings.TrimPrefix(n, "/")] = struct{}{}
		}
	}
	out := make(map[uuid.UUID]bool, len(agentIDs))
	for _, id := range agentIDs {
		_, ok := running[m.agentName(id)]
		out[id] = ok
	}
	return out, nil
}

// StopAgent implements ContainerManager. Idempotent: if Docker stopped
// or removed the container out-of-band (crash, OOM, daemon restart, the
// idle reaper), the desired post-condition — container not running — is
// already met, so a not-found error is success. Without this a
// dead-but-status='active' agent could never be stopped and so never
// restarted (the UI only offers Stop while active).
func (m *DockerManager) StopAgent(ctx context.Context, agentID uuid.UUID) error {
	unlock, err := m.lockAgentNetwork(ctx, agentID)
	if err != nil {
		return err
	}
	defer unlock()

	name := m.agentName(agentID)

	timeout := 5
	err = m.client.ContainerStop(ctx, name, dcontainer.StopOptions{Timeout: &timeout})
	if err != nil && !cerrdefs.IsNotFound(err) {
		return err
	}
	// Best-effort remove (unchanged): a not-found / already-removing
	// container is fine — the goal state is reached either way.
	if err := m.client.ContainerRemove(ctx, name, dcontainer.RemoveOptions{}); err != nil && !cerrdefs.IsNotFound(err) {
		return err
	}
	// Cache cleanup: drop the in-memory entry keyed by the container name.
	m.mu.Lock()
	delete(m.active, name)
	delete(m.lastActivity, name)
	m.mu.Unlock()
	if m.cfg.AgentNetworkPerAgent {
		if err := m.cleanupAgentNetwork(ctx, agentID); err != nil {
			return fmt.Errorf("remove agent network: %w", err)
		}
	}

	return nil
}

// RemoveImage removes a Docker image by reference.
func (m *DockerManager) RemoveImage(ctx context.Context, imageRef string) error {
	_, err := m.client.ImageRemove(ctx, imageRef, image.RemoveOptions{PruneChildren: true})
	return err
}

// InspectManifest runs a candidate image without runtime credentials or
// network access and returns its bounded stdout. The image entrypoint selects
// the one-shot behavior from AIRLOCK_AGENT_MODE.
func (m *DockerManager) InspectManifest(ctx context.Context, imageRef string) (manifest []byte, retErr error) {
	if imageRef == "" {
		return nil, errors.New("inspect manifest: image reference is required")
	}
	name := m.builderPrefix() + "manifest-" + uuid.NewString()
	containerCfg := buildManifestContainerConfig(m.cfg.InstanceID, imageRef)
	hostCfg := buildManifestHostConfig(m.cfg)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), manifestCleanupTimeout)
		defer cancel()
		if err := m.client.ContainerRemove(cleanupCtx, name, dcontainer.RemoveOptions{Force: true}); err != nil && !cerrdefs.IsNotFound(err) {
			manifest = nil
			retErr = errors.Join(retErr, fmt.Errorf("remove manifest container: %w", err))
		}
	}()

	resp, err := m.client.ContainerCreate(ctx, containerCfg, hostCfg, nil, nil, name)
	if err != nil {
		return nil, fmt.Errorf("create manifest container: %w", err)
	}

	if err := m.client.ContainerStart(ctx, resp.ID, dcontainer.StartOptions{}); err != nil {
		return nil, fmt.Errorf("start manifest container: %w", err)
	}

	statusCh, errCh := m.client.ContainerWait(ctx, resp.ID, dcontainer.WaitConditionNotRunning)
	var status dcontainer.WaitResponse
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for manifest container: %w", ctx.Err())
	case err := <-errCh:
		if err == nil {
			err = errors.New("Docker wait ended without a status")
		}
		return nil, fmt.Errorf("wait for manifest container: %w", err)
	case waitStatus, ok := <-statusCh:
		if !ok {
			return nil, errors.New("wait for manifest container: Docker wait ended without a status")
		}
		status = waitStatus
	}

	stdout := &boundedBuffer{limit: maxManifestStdoutBytes}
	stderr := &boundedBuffer{limit: maxManifestStderrBytes}
	logs, err := m.client.ContainerLogs(ctx, resp.ID, dcontainer.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("read manifest output: %w", err)
	}
	_, copyErr := stdcopy.StdCopy(stdout, stderr, logs)
	closeErr := logs.Close()
	if copyErr != nil {
		return nil, manifestError(fmt.Errorf("read manifest output: %w", copyErr), stderr)
	}
	if closeErr != nil {
		return nil, manifestError(fmt.Errorf("close manifest output: %w", closeErr), stderr)
	}

	if status.Error != nil {
		return nil, manifestError(fmt.Errorf("manifest container wait: %s", status.Error.Message), stderr)
	}
	if status.StatusCode != 0 {
		return nil, manifestError(fmt.Errorf("manifest container exited with code %d", status.StatusCode), stderr)
	}
	if err := validateManifestOutput(stdout.Bytes(), stdout.overflow); err != nil {
		return nil, manifestError(err, stderr)
	}
	return stdout.Bytes(), nil
}

// BuildConnectorBinary compiles untrusted connector source without exposing the
// Docker socket, runtime credentials, or a writable source tree.
func (m *DockerManager) BuildConnectorBinary(ctx context.Context, opts ConnectorBuildOpts) error {
	if m.cfg.AgentBuilderImage == "" {
		return errors.New("build connector: agent builder image is required")
	}
	if opts.SourceDir == "" || opts.OutputDir == "" || opts.Package == "" || opts.Filename == "" {
		return errors.New("build connector: source, output, package, and filename are required")
	}
	if filepath.Base(opts.Filename) != opts.Filename {
		return errors.New("build connector: filename must be a base name")
	}
	sourceMount, err := m.connectorPathMount(opts.SourceDir, "/workspace", true)
	if err != nil {
		return err
	}
	outputMount, err := m.connectorPathMount(opts.OutputDir, "/output", false)
	if err != nil {
		return err
	}
	mounts := []dmount.Mount{sourceMount, outputMount,
		{Type: dmount.TypeVolume, Source: m.cfg.InstanceID + "-go-mod-cache", Target: "/tmp/go-mod"},
		{Type: dmount.TypeVolume, Source: m.cfg.InstanceID + "-go-build-cache", Target: "/tmp/go-cache"},
	}
	env, err := connectorBuildEnvironment(opts.Platform)
	if err != nil {
		return err
	}
	var moduleArgs []string
	if opts.GoProxyDir != "" {
		proxyMount, err := m.connectorPathMount(opts.GoProxyDir, "/goproxy", true)
		if err != nil {
			return err
		}
		mounts = append(mounts, proxyMount)
		env = append(env, "GOPROXY=file:///goproxy,https://proxy.golang.org")
		// Dev pins content-addressed local modules after the source go.sum was
		// written. Reconcile them through an alternate file without making the
		// untrusted source mount writable.
		modFile, cleanup, err := prepareConnectorModuleFiles(opts.SourceDir, opts.OutputDir)
		if err != nil {
			return err
		}
		defer cleanup()
		moduleArgs = []string{"-mod=mod", "-modfile=/output/" + filepath.Base(modFile)}
	}
	hostCfg := buildConnectorBuildHostConfig(m.cfg, mounts)
	if opts.Platform == "" {
		listArgs := append([]string{"list"}, moduleArgs...)
		listArgs = append(listArgs, "-f={{.Name}}", opts.Package)
		listCfg := &dcontainer.Config{
			Image: m.cfg.AgentBuilderImage, User: fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			WorkingDir: "/workspace", Entrypoint: []string{"/usr/local/go/bin/go"},
			Cmd: listArgs, Env: env,
			Labels: map[string]string{labelInstance: m.cfg.InstanceID, labelResource: "connector-build"},
		}
		stdout, stderr, err := m.runConnectorContainer(ctx, "list", listCfg, hostCfg)
		if err != nil {
			return manifestError(fmt.Errorf("validate connector package: %w", err), stderr)
		}
		if strings.TrimSpace(string(stdout.Bytes())) != "main" {
			return fmt.Errorf("build connector: package %s must be main", opts.Package)
		}
	}
	buildArgs := append([]string{"build"}, moduleArgs...)
	buildArgs = append(buildArgs, "-trimpath", "-o", "/output/"+opts.Filename, opts.Package)
	cfg := &dcontainer.Config{
		Image:      m.cfg.AgentBuilderImage,
		User:       fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		WorkingDir: "/workspace",
		Entrypoint: []string{"/usr/local/go/bin/go"},
		Cmd:        buildArgs,
		Env:        env,
		Labels: map[string]string{
			labelInstance: m.cfg.InstanceID,
			labelResource: "connector-build",
		},
	}
	_, stderr, err := m.runConnectorContainer(ctx, "build", cfg, hostCfg)
	if err != nil {
		return manifestError(fmt.Errorf("build connector binary: %w", err), stderr)
	}
	return nil
}

func prepareConnectorModuleFiles(sourceDir, outputDir string) (string, func(), error) {
	goMod, err := os.ReadFile(filepath.Join(sourceDir, "go.mod"))
	if err != nil {
		return "", nil, fmt.Errorf("build connector: read go.mod: %w", err)
	}
	modFile, err := os.CreateTemp(outputDir, ".airlock-connector-*.mod")
	if err != nil {
		return "", nil, fmt.Errorf("build connector: create temporary go.mod: %w", err)
	}
	modPath := modFile.Name()
	sumPath := strings.TrimSuffix(modPath, ".mod") + ".sum"
	cleanup := func() {
		_ = os.Remove(modPath)
		_ = os.Remove(sumPath)
	}
	if _, err := modFile.Write(goMod); err != nil {
		_ = modFile.Close()
		cleanup()
		return "", nil, fmt.Errorf("build connector: write temporary go.mod: %w", err)
	}
	if err := modFile.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("build connector: close temporary go.mod: %w", err)
	}
	goSum, err := os.ReadFile(filepath.Join(sourceDir, "go.sum"))
	if err == nil {
		if err := os.WriteFile(sumPath, goSum, 0o600); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("build connector: write temporary go.sum: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		cleanup()
		return "", nil, fmt.Errorf("build connector: read go.sum: %w", err)
	}
	return modPath, cleanup, nil
}

func connectorBuildEnvironment(platform string) ([]string, error) {
	environment := []string{
		"CGO_ENABLED=0", "GOMODCACHE=/tmp/go-mod", "GOCACHE=/tmp/go-cache",
		"GOTMPDIR=/tmp/work", "GOFLAGS=-buildvcs=false -mod=readonly", "GOSUMDB=off",
	}
	if platform == "" {
		return environment, nil
	}
	target, ok := protocol.LookupTarget(platform)
	if !ok {
		return nil, fmt.Errorf("build connector: unsupported platform %q", platform)
	}
	return append(environment, target.GoEnv()...), nil
}

// InspectConnectorManifest executes only the mounted native binary. The
// read-only root, absent network, and empty environment keep source-controlled
// code away from build and runtime credentials while it declares its contract.
func (m *DockerManager) InspectConnectorManifest(ctx context.Context, binaryPath string) ([]byte, error) {
	if m.cfg.AgentBuilderImage == "" {
		return nil, errors.New("inspect connector manifest: agent builder image is required")
	}
	info, err := os.Lstat(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("inspect connector manifest: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("inspect connector manifest: binary must be a regular file")
	}
	mount, err := m.connectorPathMount(filepath.Dir(binaryPath), "/connector", true)
	if err != nil {
		return nil, err
	}
	cfg := &dcontainer.Config{
		Image:      m.cfg.AgentBuilderImage,
		User:       fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		Entrypoint: []string{"/connector/" + filepath.Base(binaryPath)},
		Env:        []string{"AIRLOCK_CONNECTOR_MODE=manifest"},
		Labels: map[string]string{
			labelInstance: m.cfg.InstanceID,
			labelResource: "connector-manifest",
		},
	}
	hostCfg := buildConnectorManifestHostConfig(m.cfg, mount)
	stdout, stderr, err := m.runConnectorContainer(ctx, "manifest", cfg, hostCfg)
	if err != nil {
		return nil, manifestError(fmt.Errorf("inspect connector manifest: %w", err), stderr)
	}
	if err := validateManifestOutput(stdout.Bytes(), stdout.overflow); err != nil {
		return nil, manifestError(err, stderr)
	}
	return stdout.Bytes(), nil
}

func buildConnectorBuildHostConfig(cfg *config.Config, mounts []dmount.Mount) *dcontainer.HostConfig {
	init := true
	return &dcontainer.HostConfig{
		Init: &init, ReadonlyRootfs: true, CapDrop: []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges"}, OomScoreAdj: 500,
		Runtime: cfg.AgentRuntime, Mounts: mounts,
		Tmpfs: map[string]string{"/tmp/work": "rw,noexec,nosuid,size=512m"},
		Resources: dcontainer.Resources{
			Memory: connectorBuildMemory, MemorySwap: connectorBuildMemory,
			PidsLimit: ptrInt64(connectorBuildPids), CPUShares: 512,
		},
	}
}

func buildConnectorManifestHostConfig(cfg *config.Config, mount dmount.Mount) *dcontainer.HostConfig {
	init := true
	return &dcontainer.HostConfig{
		Init: &init, NetworkMode: dcontainer.NetworkMode("none"), ReadonlyRootfs: true,
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"},
		OomScoreAdj: 500, Runtime: cfg.AgentRuntime, Mounts: []dmount.Mount{mount},
		Resources: dcontainer.Resources{
			Memory: manifestMemoryBytes, MemorySwap: manifestMemoryBytes,
			PidsLimit: ptrInt64(manifestPidsLimit), CPUShares: 256,
		},
	}
}

func (m *DockerManager) connectorPathMount(source, target string, readOnly bool) (dmount.Mount, error) {
	if !filepath.IsAbs(source) {
		return dmount.Mount{}, fmt.Errorf("connector sandbox path %q is not absolute", source)
	}
	if m.cfg.AgentCodegenVolume == "" || m.cfg.AgentCodegenPath == "" {
		return dmount.Mount{Type: dmount.TypeBind, Source: source, Target: target, ReadOnly: readOnly}, nil
	}
	root := filepath.Dir(m.cfg.AgentCodegenPath)
	rel, err := filepath.Rel(root, source)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return dmount.Mount{}, fmt.Errorf("connector sandbox path %q is outside shared volume root %q", source, root)
	}
	return dmount.Mount{
		Type: dmount.TypeVolume, Source: m.cfg.AgentCodegenVolume, Target: target, ReadOnly: readOnly,
		VolumeOptions: &dmount.VolumeOptions{Subpath: filepath.ToSlash(rel)},
	}, nil
}

func (m *DockerManager) runConnectorContainer(ctx context.Context, purpose string, cfg *dcontainer.Config, hostCfg *dcontainer.HostConfig) (stdout, stderr *boundedBuffer, retErr error) {
	name := m.builderPrefix() + "connector-" + purpose + "-" + uuid.NewString()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), manifestCleanupTimeout)
		defer cancel()
		if err := m.client.ContainerRemove(cleanupCtx, name, dcontainer.RemoveOptions{Force: true}); err != nil && !cerrdefs.IsNotFound(err) {
			retErr = errors.Join(retErr, fmt.Errorf("remove connector %s container: %w", purpose, err))
		}
	}()
	resp, err := m.client.ContainerCreate(ctx, cfg, hostCfg, nil, nil, name)
	if err != nil {
		return nil, nil, fmt.Errorf("create container: %w", err)
	}
	if err := m.client.ContainerStart(ctx, resp.ID, dcontainer.StartOptions{}); err != nil {
		return nil, nil, fmt.Errorf("start container: %w", err)
	}
	statusCh, errCh := m.client.ContainerWait(ctx, resp.ID, dcontainer.WaitConditionNotRunning)
	var status dcontainer.WaitResponse
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case err := <-errCh:
		if err == nil {
			err = errors.New("Docker wait ended without a status")
		}
		return nil, nil, err
	case waitStatus, ok := <-statusCh:
		if !ok {
			return nil, nil, errors.New("Docker wait ended without a status")
		}
		status = waitStatus
	}
	stdout = &boundedBuffer{limit: maxManifestStdoutBytes}
	stderr = &boundedBuffer{limit: maxManifestStderrBytes}
	logs, err := m.client.ContainerLogs(ctx, resp.ID, dcontainer.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return stdout, stderr, err
	}
	_, copyErr := stdcopy.StdCopy(stdout, stderr, logs)
	closeErr := logs.Close()
	if copyErr != nil || closeErr != nil {
		return stdout, stderr, errors.Join(copyErr, closeErr)
	}
	if status.Error != nil {
		return stdout, stderr, errors.New(status.Error.Message)
	}
	if status.StatusCode != 0 {
		return stdout, stderr, fmt.Errorf("container exited with code %d", status.StatusCode)
	}
	return stdout, stderr, nil
}

func buildManifestContainerConfig(instanceID, imageRef string) *dcontainer.Config {
	return &dcontainer.Config{
		Image: imageRef,
		Env:   []string{"AIRLOCK_AGENT_MODE=manifest"},
		Labels: map[string]string{
			labelInstance: instanceID,
			labelResource: resourceManifest,
		},
	}
}

func buildManifestHostConfig(cfg *config.Config) *dcontainer.HostConfig {
	init := true
	return &dcontainer.HostConfig{
		Init:           &init,
		NetworkMode:    dcontainer.NetworkMode("none"),
		ReadonlyRootfs: true,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		OomScoreAdj:    500,
		Runtime:        cfg.AgentRuntime,
		Resources: dcontainer.Resources{
			Memory:     manifestMemoryBytes,
			MemorySwap: manifestMemoryBytes,
			PidsLimit:  ptrInt64(manifestPidsLimit),
			CPUShares:  256,
		},
	}
}

func validateManifestOutput(stdout []byte, overflow bool) error {
	if overflow || len(stdout) > maxManifestStdoutBytes ||
		(len(stdout) == maxManifestStdoutBytes && stdout[len(stdout)-1] != '\n') {
		return errors.New("manifest exceeds 4 MiB plus one trailing newline")
	}
	payload := stdout
	if len(payload) > 0 && payload[len(payload)-1] == '\n' {
		payload = payload[:len(payload)-1]
	}
	if len(payload) == 0 {
		return errors.New("manifest output is empty")
	}
	if bytes.ContainsAny(payload, "\r\n") || !json.Valid(payload) {
		return errors.New("manifest must be exactly one JSON document on one line")
	}
	return nil
}

func manifestError(err error, stderr *boundedBuffer) error {
	diagnostic := strings.TrimSpace(string(stderr.Bytes()))
	if stderr.overflow {
		diagnostic += "\n[stderr truncated]"
	}
	if diagnostic == "" {
		return err
	}
	return fmt.Errorf("%w; stderr: %q", err, diagnostic)
}

type boundedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	if remaining < len(p) {
		b.overflow = true
	}
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

// StartToolserver starts an ephemeral toolserver container for build operations.
// The container runs the toolserver binary with the workspace mounted.
// Returns the container with a WebSocket endpoint for remote tool execution.
func (m *DockerManager) StartToolserver(ctx context.Context, opts ToolserverOpts) (*Container, error) {
	name := fmt.Sprintf("%s%d", m.builderPrefix(), time.Now().UnixNano())

	// Set -home-dir so tools that resolve $HOME (e.g. todowrite's XDG path)
	// have a writable target — the container runs as the host UID, which
	// HOME would otherwise resolve to "/" for. The agent-builder image's
	// entrypoint self-registers that UID into /etc/passwd so sudo works
	// (it refuses to run for an unknown UID).
	cmd := []string{"toolserver", "-space-dir", opts.WorkDir, "-home-dir", "/tmp/sol-home"}

	// Run as the host UID/GID so files written to the bind-mounted workspace
	// are owned by the same user, preventing permission errors on git operations.
	uid := os.Getuid()
	gid := os.Getgid()

	// Set Go env vars to writable locations since we run as non-root UID.
	env := append(opts.Env,
		"GOCACHE=/tmp/go-cache",
		"GOMODCACHE=/tmp/go-mod",
		"GONOSUMDB=*",
		"GOSUMDB=off",
		"GOFLAGS=-buildvcs=false",
	)

	containerCfg := &dcontainer.Config{
		Image:      opts.Image,
		Env:        env,
		Cmd:        cmd,
		User:       fmt.Sprintf("%d:%d", uid, gid),
		WorkingDir: opts.WorkDir,
		ExposedPorts: nat.PortSet{
			"8080/tcp": struct{}{},
		},
	}

	// Persistent volumes for Go module + build caches across codegen runs.
	// The apt-* volumes let `sudo apt-get update` (sudoers grants apt-get
	// /apt-cache NOPASSWD in the agent-builder image) keep its package
	// index across toolserver lifetimes — first install in a fresh dev
	// env pays the index download once; subsequent installs are warm.
	// Volumes are owned by root because apt only writes via sudo; the
	// host-UID toolserver process never touches them directly.
	// Cache volumes are instance-scoped so co-located instances don't share
	// (and race on) the same go-mod/go-build/apt caches.
	vp := m.cfg.InstanceID + "-"
	mounts := append(opts.Mounts,
		dmount.Mount{Type: dmount.TypeVolume, Source: vp + "go-mod-cache", Target: "/tmp/go-mod"},
		dmount.Mount{Type: dmount.TypeVolume, Source: vp + "go-build-cache", Target: "/tmp/go-cache"},
		dmount.Mount{Type: dmount.TypeVolume, Source: vp + "apt-lists", Target: "/var/lib/apt/lists"},
		dmount.Mount{Type: dmount.TypeVolume, Source: vp + "apt-cache", Target: "/var/cache/apt"},
	)

	hostCfg := buildToolserverHostConfig(m.cfg, mounts)
	if m.cfg.AgentHostGateway {
		hostCfg.ExtraHosts = []string{"host.docker.internal:host-gateway"}
	}

	c, err := m.createAndStart(ctx, name, containerCfg, hostCfg, m.cfg.DockerNetwork)
	if err != nil {
		return nil, fmt.Errorf("start toolserver: %w", err)
	}
	m.setToolserverLogCallback(name, opts.LogCallback)

	if err := m.waitHealthy(ctx, c, 15*time.Second); err != nil {
		m.captureToolserverDiagnostics(context.Background(), name, "failed to start")
		m.client.ContainerRemove(context.Background(), c.ID, dcontainer.RemoveOptions{Force: true})
		m.clearToolserverDiagnostics(name)
		return nil, fmt.Errorf("toolserver health check: %w", err)
	}

	m.logger.Info("toolserver started", zap.String("container", name), zap.String("endpoint", c.Endpoint))
	return c, nil
}

func buildToolserverHostConfig(cfg *config.Config, mounts []dmount.Mount) *dcontainer.HostConfig {
	init := true
	hc := &dcontainer.HostConfig{
		Mounts:      mounts,
		Init:        &init,
		CapDrop:     []string{"AUDIT_WRITE", "KILL", "MKNOD", "NET_BIND_SERVICE", "NET_RAW"},
		OomScoreAdj: 500,
		Resources: dcontainer.Resources{
			PidsLimit: ptrInt64(2048),
			CPUShares: 512,
		},
	}
	if cfg.AgentMemoryLimitBytes > 0 {
		hc.Resources.Memory = cfg.AgentMemoryLimitBytes
		hc.Resources.MemorySwap = cfg.AgentMemoryLimitBytes
	}
	return hc
}

// StopToolserver stops and removes an ephemeral toolserver container.
func (m *DockerManager) StopToolserver(ctx context.Context, name string) error {
	if info, err := m.client.ContainerInspect(ctx, name); err == nil && info.State != nil && !info.State.Running {
		m.captureToolserverDiagnostics(ctx, name, "exited unexpectedly")
	}
	defer m.clearToolserverDiagnostics(name)
	timeout := 5
	if err := m.client.ContainerStop(ctx, name, dcontainer.StopOptions{Timeout: &timeout}); err != nil {
		m.logger.Warn("failed to stop toolserver", zap.String("name", name), zap.Error(err))
	}
	return m.client.ContainerRemove(ctx, name, dcontainer.RemoveOptions{Force: true})
}

// KillToolserver force-removes an ephemeral toolserver container without
// waiting for graceful shutdown. RemoveOptions{Force: true} sends SIGKILL
// and removes in one call, so any in-flight tool execution dies
// immediately. Used by the build-cancellation path: graceful shutdown is
// 5+ seconds of dead air during which the toolserver keeps running its
// in-flight tool (e.g. a long `bash go build`) and emitting log lines —
// which makes the cancel feel like it didn't take. Idempotent: returns
// nil/NotFound if the container is already gone.
func (m *DockerManager) KillToolserver(ctx context.Context, name string) error {
	defer m.clearToolserverDiagnostics(name)
	return m.client.ContainerRemove(ctx, name, dcontainer.RemoveOptions{Force: true})
}

// CaptureToolserverDiagnostics snapshots abnormal tool runtime state/logs.
func (m *DockerManager) CaptureToolserverDiagnostics(ctx context.Context, name, reason string) error {
	return m.captureToolserverDiagnostics(ctx, name, reason)
}

func (m *DockerManager) setToolserverLogCallback(name string, cb func(string)) {
	if cb == nil {
		return
	}
	m.mu.Lock()
	m.toolserverLogCallbacks[name] = cb
	m.mu.Unlock()
}

func (m *DockerManager) getToolserverLogCallback(name string) func(string) {
	m.mu.Lock()
	cb := m.toolserverLogCallbacks[name]
	m.mu.Unlock()
	return cb
}

func (m *DockerManager) clearToolserverDiagnostics(name string) {
	m.mu.Lock()
	delete(m.toolserverLogCallbacks, name)
	delete(m.toolserverDiagCaptured, name)
	m.mu.Unlock()
}

func (m *DockerManager) markToolserverDiagnosticsCaptured(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.toolserverDiagCaptured[name] {
		return false
	}
	m.toolserverDiagCaptured[name] = true
	return true
}

func (m *DockerManager) captureToolserverDiagnostics(ctx context.Context, name, reason string) error {
	if !m.markToolserverDiagnosticsCaptured(name) {
		return nil
	}
	cb := m.getToolserverLogCallback(name)
	if cb == nil {
		return nil
	}

	info, inspectErr := m.client.ContainerInspect(ctx, name)
	if inspectErr != nil {
		m.logger.Warn("inspect toolserver for diagnostics", zap.String("name", name), zap.Error(inspectErr))
		cb("[error] build tool runtime failed; diagnostics unavailable")
		return inspectErr
	}

	stateLine := toolserverStateLine(reason, info.State)
	cb(stateLine)
	if info.State != nil {
		m.logger.Warn("toolserver diagnostics captured",
			zap.String("name", name),
			zap.String("reason", reason),
			zap.String("status", string(info.State.Status)),
			zap.Bool("running", info.State.Running),
			zap.Int("exit_code", info.State.ExitCode),
			zap.Bool("oom_killed", info.State.OOMKilled),
			zap.String("state_error", info.State.Error),
		)
	} else {
		m.logger.Warn("toolserver diagnostics captured", zap.String("name", name), zap.String("reason", reason))
	}

	lines, err := m.toolserverLogTail(ctx, name, 200)
	if err != nil {
		m.logger.Warn("read toolserver logs", zap.String("name", name), zap.Error(err))
		return err
	}
	if len(lines) == 0 {
		return nil
	}
	cb("[error] build tool runtime log tail:")
	for _, line := range lines {
		cb("[tool runtime] " + line)
	}
	return nil
}

func toolserverStateLine(reason string, state *dcontainer.State) string {
	if reason == "" {
		reason = "failed"
	}
	if state == nil {
		return "[error] build tool runtime " + reason
	}

	parts := []string{"[error] build tool runtime " + reason}
	if state.Running {
		parts = append(parts, "still running")
	} else {
		parts = append(parts, "status="+string(state.Status))
		parts = append(parts, fmt.Sprintf("exitCode=%d", state.ExitCode))
	}
	if state.OOMKilled {
		parts = append(parts, "out of memory")
	}
	if state.Error != "" {
		parts = append(parts, "error="+state.Error)
	}
	return strings.Join(parts, "; ")
}

func (m *DockerManager) toolserverLogTail(ctx context.Context, name string, tail int) ([]string, error) {
	logs, err := m.client.ContainerLogs(ctx, name, dcontainer.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", tail),
	})
	if err != nil {
		return nil, err
	}
	defer logs.Close()

	var buf bytes.Buffer
	if _, err := stdcopy.StdCopy(&buf, &buf, logs); err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(buf.String()))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		if isRoutineToolserverLogLine(line) {
			continue
		}
		if len(line) > 4000 {
			line = line[:4000] + "..."
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func isRoutineToolserverLogLine(line string) bool {
	return strings.Contains(line, "toolserver listening on") || strings.Contains(line, "shutting down...")
}

// buildAgentHostConfig assembles the hardened HostConfig for an agent
// runtime container. Agents are arbitrary user/LLM-authored code, so the
// container is the trust boundary, not the in-container uid:
//
//   - CapDrop ALL — the agent needs no capabilities (it serves HTTP on
//     :8080 and shells out to nothing; exec runs in the separate
//     toolserver), so even container-root is powerless.
//   - no-new-privileges — defangs any setuid binary or sudo a malicious
//     setup.sh baked into the image at build time; it can't re-elevate.
//   - PidsLimit / CPUShares — bound forks and give the agent a lower CPU
//     weight than infra (default 1024), so it can't fork-bomb or starve
//     airlock/postgres. Both are environment-independent (no host sizing).
//   - OomScoreAdj 500 — under host memory pressure the kernel kills an
//     agent before infra, so the host survives without a concurrency cap.
//   - Memory — capped only when the operator sets AGENT_MEMORY_LIMIT; the
//     host's size is unknown, and OomScoreAdj already protects it.
//
// Default seccomp is intentionally left in place (not unconfined).
//
// The host-gateway alias is explicit because host access depends on where
// Airlock runs, not where agent library source comes from.
func buildAgentHostConfig(cfg *config.Config) *dcontainer.HostConfig {
	hc := &dcontainer.HostConfig{
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges"},
		OomScoreAdj: 500,
		Runtime:     cfg.AgentRuntime, // "" = Docker default (runc); "runsc" = gVisor
		Resources: dcontainer.Resources{
			PidsLimit: ptrInt64(1024),
			CPUShares: 512,
		},
	}
	if cfg.AgentMemoryLimitBytes > 0 {
		// MemorySwap == Memory disables swap, making the limit a hard cap.
		hc.Resources.Memory = cfg.AgentMemoryLimitBytes
		hc.Resources.MemorySwap = cfg.AgentMemoryLimitBytes
	}
	if cfg.AgentHostGateway {
		hc.ExtraHosts = []string{"host.docker.internal:host-gateway"}
	}
	return hc
}

func ptrInt64(v int64) *int64 { return &v }

// networkConfig builds the Docker NetworkingConfig attaching a container to
// networkName (empty = the daemon default network). Managed agent runtimes use
// their dedicated internal network; toolserver/build containers use the infra
// network.
func networkConfig(networkName string) *network.NetworkingConfig {
	netCfg := &network.NetworkingConfig{}
	if networkName != "" {
		netCfg.EndpointsConfig = map[string]*network.EndpointSettings{
			networkName: {},
		}
	}
	return netCfg
}

func agentNetworkCreateOptions(instanceID, agentID string, internal bool) network.CreateOptions {
	return network.CreateOptions{
		Driver:   "bridge",
		Internal: internal,
		Labels: map[string]string{
			labelInstance: instanceID,
			labelResource: resourceAgentNet,
			labelAgentID:  agentID,
		},
	}
}

func validateAgentNetworkIdentity(info network.Inspect, instanceID, agentID string) error {
	if info.Driver != "bridge" ||
		info.Labels[labelInstance] != instanceID ||
		info.Labels[labelResource] != resourceAgentNet ||
		info.Labels[labelAgentID] != agentID {
		return fmt.Errorf("network %s does not match managed agent network policy", info.Name)
	}
	return nil
}

func validateAgentNetwork(info network.Inspect, instanceID, agentID string, internal bool) error {
	if err := validateAgentNetworkIdentity(info, instanceID, agentID); err != nil {
		return err
	}
	if info.Internal != internal {
		return fmt.Errorf("network %s internal=%t, want %t", info.Name, info.Internal, internal)
	}
	return nil
}

func agentDependencyEndpointSettings(aliases []string) *network.EndpointSettings {
	return &network.EndpointSettings{
		Aliases:    aliases,
		GwPriority: -1,
	}
}

func (m *DockerManager) lockAgentNetwork(ctx context.Context, agentID uuid.UUID) (func(), error) {
	if !m.cfg.AgentNetworkPerAgent {
		return func() {}, nil
	}
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire agent network lock connection: %w", err)
	}
	key := m.cfg.InstanceID + "/" + agentID.String()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, $2))`, key, agentNetworkLockID); err != nil {
		conn.Release()
		return nil, fmt.Errorf("acquire agent network lock: %w", err)
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, $2))`, key, agentNetworkLockID)
		conn.Release()
	}, nil
}

func (m *DockerManager) agentNetworkDependencies(ctx context.Context, runningOnly bool) (map[string]dcontainer.Summary, error) {
	f := filters.NewArgs(filters.Arg("label", config.LabelAgentNetworkAccess+"="+m.cfg.InstanceID))
	containers, err := m.client.ContainerList(ctx, dcontainer.ListOptions{All: !runningOnly, Filters: f})
	if err != nil {
		return nil, fmt.Errorf("list agent network dependencies: %w", err)
	}
	dependencies := make(map[string]dcontainer.Summary, len(containers))
	for _, dependency := range containers {
		if runningOnly && dependency.State != "running" {
			continue
		}
		info, err := m.client.ContainerInspect(ctx, dependency.ID)
		if err != nil {
			return nil, fmt.Errorf("inspect agent network dependency %s: %w", dependency.ID, err)
		}
		if runningOnly && (info.NetworkSettings == nil || info.NetworkSettings.Networks[m.cfg.AgentNetwork] == nil) {
			return nil, fmt.Errorf("agent network dependency %s is not attached to seed network %s", dependency.ID, m.cfg.AgentNetwork)
		}
		dependencies[dependency.ID] = dependency
	}
	return dependencies, nil
}

func (m *DockerManager) ensureAgentNetwork(ctx context.Context, agentID uuid.UUID) error {
	name := m.agentNetworkName(agentID)
	internal := m.networkPolicy.Internal(agentID)
	info, err := m.client.NetworkInspect(ctx, name, network.InspectOptions{})
	if err == nil {
		if err := validateAgentNetworkIdentity(info, m.cfg.InstanceID, agentID.String()); err != nil {
			return err
		}
		if info.Internal != internal {
			// Network mutability is deliberately narrow in Docker. Disconnect all
			// endpoints and recreate the owned network when a distribution's
			// policy changes. StartAgent will replace the now-disconnected runtime.
			for id := range info.Containers {
				if err := m.client.NetworkDisconnect(ctx, info.ID, id, true); err != nil && !cerrdefs.IsNotFound(err) {
					return fmt.Errorf("disconnect endpoint %s from network %s: %w", id, name, err)
				}
			}
			if err := m.client.NetworkRemove(ctx, info.ID); err != nil && !cerrdefs.IsNotFound(err) {
				return fmt.Errorf("remove network %s for policy change: %w", name, err)
			}
			err = cerrdefs.ErrNotFound
		}
	}
	if cerrdefs.IsNotFound(err) {
		if _, err = m.client.NetworkCreate(ctx, name, agentNetworkCreateOptions(m.cfg.InstanceID, agentID.String(), internal)); err != nil {
			if !cerrdefs.IsAlreadyExists(err) {
				return fmt.Errorf("create managed network %s: %w", name, err)
			}
		}
		info, err = m.client.NetworkInspect(ctx, name, network.InspectOptions{})
	}
	if err != nil {
		return fmt.Errorf("inspect managed network %s: %w", name, err)
	}
	if err := validateAgentNetwork(info, m.cfg.InstanceID, agentID.String(), internal); err != nil {
		return err
	}

	dependencies, err := m.agentNetworkDependencies(ctx, true)
	if err != nil {
		return err
	}
	if len(dependencies) == 0 {
		return fmt.Errorf("no trusted dependencies have %s=%s", config.LabelAgentNetworkAccess, m.cfg.InstanceID)
	}
	for id, dependency := range dependencies {
		if _, connected := info.Containers[id]; connected {
			continue
		}
		aliases := strings.FieldsFunc(dependency.Labels[config.LabelAgentNetworkAliases], func(r rune) bool {
			return r == ',' || r == ' '
		})
		if len(aliases) == 0 {
			return fmt.Errorf("agent network dependency %s has no %s label", id, config.LabelAgentNetworkAliases)
		}
		if err := m.client.NetworkConnect(ctx, info.ID, id, agentDependencyEndpointSettings(aliases)); err != nil {
			return fmt.Errorf("connect dependency %s to network %s: %w", id, name, err)
		}
	}
	return nil
}

func (m *DockerManager) cleanupAgentNetwork(ctx context.Context, agentID uuid.UUID) error {
	name := m.agentNetworkName(agentID)
	info, err := m.client.NetworkInspect(ctx, name, network.InspectOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateAgentNetworkIdentity(info, m.cfg.InstanceID, agentID.String()); err != nil {
		return err
	}
	dependencies, err := m.agentNetworkDependencies(ctx, false)
	if err != nil {
		return err
	}
	for id := range info.Containers {
		if _, trusted := dependencies[id]; !trusted {
			return nil
		}
	}
	for id := range info.Containers {
		if err := m.client.NetworkDisconnect(ctx, info.ID, id, true); err != nil && !cerrdefs.IsNotFound(err) {
			return fmt.Errorf("disconnect dependency %s from network %s: %w", id, name, err)
		}
	}
	if err := m.client.NetworkRemove(ctx, info.ID); err != nil && !cerrdefs.IsNotFound(err) {
		return err
	}
	return nil
}

func (m *DockerManager) pruneAgentNetworks(ctx context.Context) {
	if !m.cfg.AgentNetworkPerAgent {
		return
	}
	f := filters.NewArgs(
		filters.Arg("label", labelInstance+"="+m.cfg.InstanceID),
		filters.Arg("label", labelResource+"="+resourceAgentNet),
	)
	networks, err := m.client.NetworkList(ctx, network.ListOptions{Filters: f})
	if err != nil {
		m.logger.Warn("prune: failed to list agent networks", zap.Error(err))
		return
	}
	for _, candidate := range networks {
		agentID, err := uuid.Parse(candidate.Labels[labelAgentID])
		if err != nil {
			m.logger.Warn("prune: managed agent network has invalid agent label", zap.String("network", candidate.Name))
			continue
		}
		unlock, err := m.lockAgentNetwork(ctx, agentID)
		if err != nil {
			m.logger.Warn("prune: failed to lock agent network", zap.String("network", candidate.Name), zap.Error(err))
			continue
		}
		info, inspectErr := m.client.NetworkInspect(ctx, candidate.ID, network.InspectOptions{})
		dependencies, dependencyErr := m.agentNetworkDependencies(ctx, false)
		hasRuntime := false
		if inspectErr == nil && dependencyErr == nil {
			for id := range info.Containers {
				if _, trusted := dependencies[id]; !trusted {
					hasRuntime = true
					break
				}
			}
		}
		switch {
		case inspectErr != nil:
			err = inspectErr
		case dependencyErr != nil:
			err = dependencyErr
		case hasRuntime:
			err = m.ensureAgentNetwork(ctx, agentID)
		default:
			err = m.cleanupAgentNetwork(ctx, agentID)
		}
		unlock()
		if err != nil {
			m.logger.Warn("prune: failed to reconcile agent network", zap.String("network", candidate.Name), zap.Error(err))
		}
	}
}

func (m *DockerManager) createAndStart(ctx context.Context, name string, cfg *dcontainer.Config, hostCfg *dcontainer.HostConfig, networkName string) (*Container, error) {
	if err := m.client.ContainerRemove(ctx, name, dcontainer.RemoveOptions{Force: true}); err != nil && !cerrdefs.IsNotFound(err) {
		m.logger.Warn("failed to remove existing container", zap.String("name", name), zap.Error(err))
	}

	// Stamp the ownership label on every container (agent + toolserver) so
	// list/prune calls scoped by instanceFilter never touch another
	// instance's resources. This is the single chokepoint both paths funnel
	// through.
	if cfg.Labels == nil {
		cfg.Labels = map[string]string{}
	}
	cfg.Labels[labelInstance] = m.cfg.InstanceID

	netCfg := networkConfig(networkName)

	resp, err := m.client.ContainerCreate(ctx, cfg, hostCfg, netCfg, nil, name)
	if err != nil {
		return nil, fmt.Errorf("create container %s: %w", name, err)
	}

	if err := m.client.ContainerStart(ctx, resp.ID, dcontainer.StartOptions{}); err != nil {
		_ = m.client.ContainerRemove(context.Background(), resp.ID, dcontainer.RemoveOptions{Force: true})
		return nil, fmt.Errorf("start container %s: %w", name, err)
	}

	endpoint, err := m.getEndpoint(ctx, resp.ID)
	if err != nil {
		_ = m.client.ContainerRemove(context.Background(), resp.ID, dcontainer.RemoveOptions{Force: true})
		return nil, err
	}

	return &Container{
		ID:       resp.ID,
		Name:     name,
		Endpoint: endpoint,
		Network:  networkName,
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

	image := ""
	token := ""
	networkName := ""
	agentID := uuid.Nil
	if info.Config != nil {
		image = info.Config.Image
		token = agentTokenFromEnv(info.Config.Env)
		agentID, _ = uuid.Parse(info.Config.Labels[labelAgentID])
	}
	if info.NetworkSettings != nil {
		for name := range info.NetworkSettings.Networks {
			networkName = name
			break
		}
	}
	return &Container{
		ID:       info.ID,
		Name:     name,
		Endpoint: endpoint,
		Token:    token,
		Image:    image,
		Network:  networkName,
		AgentID:  agentID,
	}, nil
}

// LockSwap acquires the per-agent container-swap mutex. See the
// ContainerManager interface comment for the design rationale.
func (m *DockerManager) LockSwap(agentID uuid.UUID) func() {
	key := agentID.String()
	mu, _ := m.swapMu.LoadOrStore(key, &sync.Mutex{})
	mux := mu.(*sync.Mutex)
	mux.Lock()
	return mux.Unlock
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

// MarkBusy records the start of an in-flight request to an agent
// container. While the in-flight count is above zero the idle reaper
// skips the container, so a run that outlasts idleTimeout is not
// stopped mid-execution. Pair every MarkBusy with exactly one MarkIdle.
func (m *DockerManager) MarkBusy(agentID uuid.UUID) {
	name := m.agentName(agentID)
	m.mu.Lock()
	m.inFlight[name]++
	m.lastActivity[name] = time.Now()
	m.mu.Unlock()
}

// MarkIdle records the end of an in-flight request. It also refreshes
// the idle clock so the timeout is measured from the end of the last
// request rather than its start.
func (m *DockerManager) MarkIdle(agentID uuid.UUID) {
	name := m.agentName(agentID)
	m.mu.Lock()
	if m.inFlight[name] > 0 {
		m.inFlight[name]--
	}
	if m.inFlight[name] == 0 {
		delete(m.inFlight, name)
	}
	m.lastActivity[name] = time.Now()
	m.mu.Unlock()
}

type stopTarget struct {
	name    string
	id      string
	agentID uuid.UUID
}

// idleContainersToStop selects agent containers whose idle window has
// elapsed and that have no in-flight request. Caller must hold m.mu.
func (m *DockerManager) idleContainersToStop(now time.Time) []stopTarget {
	var toStop []stopTarget
	for name, lastUse := range m.lastActivity {
		if m.inFlight[name] > 0 {
			continue
		}
		if now.Sub(lastUse) > m.idleTimeout {
			if c, ok := m.active[name]; ok {
				toStop = append(toStop, stopTarget{name: name, id: c.ID, agentID: c.AgentID})
			}
		}
	}
	return toStop
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
			toStop := m.idleContainersToStop(time.Now())
			for _, s := range toStop {
				delete(m.active, s.name)
				delete(m.lastActivity, s.name)
			}
			m.mu.Unlock()

			for _, s := range toStop {
				m.logger.Info("stopping idle container", zap.String("name", s.name))
				ctx := context.Background()
				unlock, err := m.lockAgentNetwork(ctx, s.agentID)
				if err != nil {
					m.logger.Warn("failed to lock idle agent network", zap.String("name", s.name), zap.Error(err))
					continue
				}
				timeout := 5
				m.client.ContainerStop(ctx, s.id, dcontainer.StopOptions{Timeout: &timeout})
				m.client.ContainerRemove(ctx, s.id, dcontainer.RemoveOptions{})
				if m.cfg.AgentNetworkPerAgent && s.agentID != uuid.Nil {
					if err := m.cleanupAgentNetwork(ctx, s.agentID); err != nil {
						m.logger.Warn("failed to remove idle agent network", zap.String("name", s.name), zap.Error(err))
					}
				}
				unlock()
			}
			m.pruneAgentNetworks(context.Background())
		}
	}
}
