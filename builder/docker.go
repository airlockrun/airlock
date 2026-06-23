package builder

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/scaffold"
	"go.uber.org/zap"
)

// buildImage builds a Docker image from the agent's directory.
// dockerfilePath, when non-empty, is passed via `docker build -f` so the
// build uses an out-of-context Dockerfile (lets airlock always build
// against its current template without overwriting the user-committed
// Dockerfile in contextDir). When empty, docker looks for Dockerfile
// inside contextDir as usual.
// If logFn is non-nil, Docker build output is streamed line by line.
// Returns the image tag.
// goproxyDir, when non-empty (dev), is supplied as the `goproxy` build
// context so the agent's owned libs resolve from the local file proxy
// instead of the public proxy. Empty (prod) leaves the Dockerfile's empty
// scratch stage in place — modules resolve from the public proxy.
func buildImage(ctx context.Context, cfg *config.Config, agentID, contextDir, commitHash, dockerfilePath, goproxyDir string, logFn func(string)) (string, error) {
	tag := fmt.Sprintf("%s:%s", agentID, commitHash[:12])
	if cfg.AgentRegistryURL != "" {
		tag = fmt.Sprintf("%s/%s", cfg.AgentRegistryURL, tag)
	}

	// Rootless BuildKit path (prod): build via a remote buildx builder backed
	// by the rootless buildkitd container, so the agent's untrusted setup.sh
	// runs as root *inside buildkitd* (an unprivileged host uid) rather than
	// on the host's root dockerd. --load imports the result into the local
	// image store; --push (registry mode) goes straight to the registry, so
	// no separate `docker push` is needed.
	if cfg.BuildkitHost != "" {
		if err := ensureBuildxBuilder(cfg.BuildkitHost, cfg.InstanceID); err != nil {
			return "", err
		}
		args := buildxBuildArgs(tag, dockerfilePath, contextDir, goproxyDir, cfg.AgentRegistryURL != "", cfg.InstanceID)
		cmd := exec.CommandContext(ctx, "docker", args...)
		if logFn != nil {
			return tag, runAndStream(cmd, logFn)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("docker buildx build: %s: %w", strings.TrimSpace(string(out)), err)
		}
		return tag, nil
	}

	// Legacy path (dev / no buildkitd): build on the host docker daemon.
	args := []string{"build", "-t", tag}
	args = append(args, instanceLabelArg(cfg.InstanceID)...)
	if goproxyDir != "" {
		args = append(args, "--build-context", "goproxy="+goproxyDir)
	}
	if dockerfilePath != "" {
		args = append(args, "-f", dockerfilePath)
	}
	args = append(args, contextDir)

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(cmd.Environ(), "DOCKER_BUILDKIT=1")

	if logFn != nil {
		return tag, runAndStream(cmd, logFn)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker build: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Push to registry if configured
	if cfg.AgentRegistryURL != "" {
		pushCmd := exec.CommandContext(ctx, "docker", "push", tag)
		out, err := pushCmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("docker push: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}

	return tag, nil
}

// buildxBuilderBase is the prefix for the buildx builder airlock creates
// pointing at the rootless buildkitd (BUILDKIT_HOST). The actual name is
// instance-scoped (buildxBuilderName) because buildx builders live in
// ~/.docker/buildx — per-user, shared across daemons — so co-located
// instances must not collide and cross-route builds to each other's buildkitd.
const buildxBuilderBase = "airlock-rootless"

// buildxBuilderName is the instance-scoped buildx builder name. Stable per
// instance so it's reused across that instance's builds.
func buildxBuilderName(instanceID string) string { return buildxBuilderBase + "-" + instanceID }

// instanceLabelArg returns the `--label run.airlock.instance=<id>` pair that
// stamps the ownership label on a built agent image (matching the prune-time
// filter in container.DockerManager).
func instanceLabelArg(instanceID string) []string {
	return []string{"--label", config.LabelInstance + "=" + instanceID}
}

// buildxBuildArgs builds the `docker buildx build` argv for an agent image.
// push=true emits to the registry; otherwise the result is --loaded into the
// local docker image store. goproxyDir, when set (dev), is wired as the
// `goproxy` named build context.
func buildxBuildArgs(tag, dockerfilePath, contextDir, goproxyDir string, push bool, instanceID string) []string {
	args := []string{"buildx", "build", "--builder", buildxBuilderName(instanceID), "--progress=plain", "-t", tag}
	args = append(args, instanceLabelArg(instanceID)...)
	if push {
		args = append(args, "--push")
	} else {
		args = append(args, "--load")
	}
	if goproxyDir != "" {
		args = append(args, "--build-context", "goproxy="+goproxyDir)
	}
	if dockerfilePath != "" {
		args = append(args, "-f", dockerfilePath)
	}
	args = append(args, contextDir)
	return args
}

var (
	buildxOnce sync.Once
	buildxErr  error
)

// ensureBuildxBuilder lazily creates the remote-driver buildx builder that
// targets the rootless buildkitd at host (e.g. unix:///run/buildkit/buildkitd.sock).
// Idempotent: a builder that already exists is reused. Runs once per process.
func ensureBuildxBuilder(host, instanceID string) error {
	buildxOnce.Do(func() {
		ctx := context.Background()
		name := buildxBuilderName(instanceID)
		if err := exec.CommandContext(ctx, "docker", "buildx", "inspect", name).Run(); err == nil {
			return // already exists
		}
		out, err := exec.CommandContext(ctx, "docker", "buildx", "create",
			"--name", name, "--driver", "remote", host).CombinedOutput()
		if err != nil {
			buildxErr = fmt.Errorf("buildx create (remote %s): %s: %w", host, strings.TrimSpace(string(out)), err)
		}
	})
	return buildxErr
}

// WarmBuildCache pre-downloads Go module dependencies so that the first real
// agent build hits a warm cache. Materializes a real scaffold and runs a full
// docker build (same Dockerfile.tmpl + go.mod.tmpl as real builds), then
// removes the throwaway image. The cache mounts persist.
func (b *BuildService) WarmBuildCache(ctx context.Context) {
	dir, err := b.makeCodegenTempDir("airlock-cache-warm-*")
	if err != nil {
		b.logger.Warn("warm cache: create temp dir", zap.Error(err))
		return
	}
	defer os.RemoveAll(dir)

	sdkVer, verErr := b.agentSDKVersion()
	if verErr != nil {
		b.logger.Warn("warm cache: agent sdk version", zap.Error(verErr))
		return
	}

	// Materialize a real scaffold — same templates as actual agent builds.
	if err := scaffold.Materialize(dir, scaffold.ScaffoldData{
		AgentID:         "cache-warm",
		Module:          "agent",
		GoVersion:       buildGoVersion,
		AgentSDKVersion: sdkVer,
		AgentBaseImage:  b.cfg.AgentBaseImage,
	}); err != nil {
		b.logger.Warn("warm cache: scaffold", zap.Error(err))
		return
	}

	// Overwrite main.go with a minimal stub — the warm cache only needs to
	// populate the Go module cache, not produce a working agent binary.
	// The scaffold's main.go imports the views package which doesn't resolve
	// in an isolated Docker build context.
	stub := []byte("package main\n\nimport _ \"github.com/a-h/templ\"\nimport _ \"github.com/airlockrun/agentsdk\"\n\nfunc main() {}\n")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), stub, 0o644); err != nil {
		b.logger.Warn("warm cache: write stub main.go", zap.Error(err))
		return
	}

	// Dev: generate the local lib proxy so the owned libs resolve from live
	// source. Prod: no proxy — the build resolves published versions from the
	// public proxy.
	proxyDir, cleanup, err := b.ensureLibProxy()
	if err != nil {
		b.logger.Warn("warm cache: generate lib proxy", zap.Error(err))
		return
	}
	defer cleanup()

	// Instance-scoped throwaway tag so concurrent warms on a shared daemon
	// don't `docker rmi` each other (legacy path).
	tag := b.cfg.InstanceID + "-cache-warm:latest"
	var cmd *exec.Cmd
	if b.cfg.BuildkitHost != "" {
		// Rootless BuildKit: warm buildkitd's own (persistent) cache. No
		// output requested (no --load/--push), so the throwaway image is
		// discarded by buildkitd — nothing to `docker rmi` afterwards.
		if err := ensureBuildxBuilder(b.cfg.BuildkitHost, b.cfg.InstanceID); err != nil {
			b.logger.Warn("warm cache: buildx builder", zap.Error(err))
			return
		}
		args := []string{"buildx", "build", "--builder", buildxBuilderName(b.cfg.InstanceID), "--progress=plain"}
		if proxyDir != "" {
			args = append(args, "--build-context", "goproxy="+proxyDir)
		}
		args = append(args, dir)
		cmd = exec.CommandContext(ctx, "docker", args...)
	} else {
		args := []string{"build", "-t", tag}
		if proxyDir != "" {
			args = append(args, "--build-context", "goproxy="+proxyDir)
		}
		args = append(args, dir)
		cmd = exec.CommandContext(ctx, "docker", args...)
		cmd.Env = append(cmd.Environ(), "DOCKER_BUILDKIT=1")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		b.logger.Warn("warm cache: docker build failed", zap.String("output", string(out)), zap.Error(err))
		return
	}

	// Legacy build produced a tagged image; remove it (cache mounts persist).
	if b.cfg.BuildkitHost == "" {
		_ = exec.CommandContext(ctx, "docker", "rmi", tag).Run()
	}

	b.logger.Info("build cache warmed")
}

// WarmRuntimeCaches seeds the named volumes that the build-prompt loop's
// direct `go mod tidy` / `go build` invocations consume — distinct from
// the BuildKit cache mount that WarmBuildCache populates. The agent-builder
// container at runtime sets GOMODCACHE=/tmp/go-mod and GOCACHE=/tmp/go-cache
// (see container/docker.go) backed by the instance-scoped
// <instance>-go-mod-cache and <instance>-go-build-cache Docker named
// volumes. Without this seed, the
// first build-prompt iteration pays full download cost for ~25 modules
// in agentsdk+sol's transitive dep tree. The volumes persist across
// airlock restarts.
func (b *BuildService) WarmRuntimeCaches(ctx context.Context) {
	if b.cfg.AgentBuilderImage == "" {
		b.logger.Warn("warm runtime caches: agent-builder image empty — skipping")
		return
	}

	dir, err := b.makeCodegenTempDir("airlock-runtime-warm-*")
	if err != nil {
		b.logger.Warn("warm runtime caches: create temp dir", zap.Error(err))
		return
	}
	defer os.RemoveAll(dir)

	sdkVer, verErr := b.agentSDKVersion()
	if verErr != nil {
		b.logger.Warn("warm runtime caches: agent sdk version", zap.Error(verErr))
		return
	}

	if err := scaffold.Materialize(dir, scaffold.ScaffoldData{
		AgentID:         "runtime-warm",
		Module:          "agent",
		GoVersion:       buildGoVersion,
		AgentSDKVersion: sdkVer,
		AgentBaseImage:  b.cfg.AgentBaseImage,
	}); err != nil {
		b.logger.Warn("warm runtime caches: scaffold", zap.Error(err))
		return
	}

	// Stub main.go — same rationale as WarmBuildCache. We just want a
	// successful `go mod tidy && go build` to populate the volumes.
	stub := []byte("package main\n\nimport _ \"github.com/a-h/templ\"\nimport _ \"github.com/airlockrun/agentsdk\"\n\nfunc main() {}\n")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), stub, 0o644); err != nil {
		b.logger.Warn("warm runtime caches: write stub main.go", zap.Error(err))
		return
	}

	uid := os.Getuid()
	gid := os.Getgid()

	// Dev: generate the local lib proxy. Prod: empty — public proxy.
	proxyDir, cleanup, err := b.ensureLibProxy()
	if err != nil {
		b.logger.Warn("warm runtime caches: generate lib proxy", zap.Error(err))
		return
	}
	defer cleanup()

	// Workspace mount: in compose/docker-in-docker mode, mount the named
	// volume that contains AgentCodegenPath so the daemon resolves both
	// ends through the same managed volume; the sibling sees `dir` at
	// the same absolute path airlock used. In dev/host mode, bind-mount
	// `dir` at /workspace as before.
	var workspaceMount, workspaceDir string
	if b.cfg.AgentCodegenVolume != "" && b.cfg.AgentCodegenPath != "" {
		// Mount the volume at the parent of AgentCodegenPath (i.e.
		// /var/lib/airlock when path is /var/lib/airlock/codegen) so
		// the absolute path stays valid.
		workspaceMount = b.cfg.AgentCodegenVolume + ":" + filepath.Dir(b.cfg.AgentCodegenPath)
		workspaceDir = dir
	} else {
		workspaceMount = dir + ":/workspace"
		workspaceDir = "/workspace"
	}

	// Cache volume names are instance-scoped — must match StartToolserver's
	// mounts so the volume seeded here is the one the build-prompt loop's
	// toolserver consumes.
	vp := b.cfg.InstanceID + "-"
	args := []string{
		"run", "--rm",
		"--label", config.LabelInstance + "=" + b.cfg.InstanceID,
		"--user", fmt.Sprintf("%d:%d", uid, gid),
		"-e", "GOMODCACHE=/tmp/go-mod",
		"-e", "GOCACHE=/tmp/go-cache",
		"-e", "GOFLAGS=-buildvcs=false",
		// Sum DB tracking files live at $GOPATH/pkg/sumdb/, which is
		// root-owned in the image while we run as the host UID. Disable
		// the lookup entirely — the public proxy and the local lib proxy
		// serve content we don't authenticate via sum.golang.org.
		"-e", "GOSUMDB=off",
		"-v", vp + "go-mod-cache:/tmp/go-mod",
		"-v", vp + "go-build-cache:/tmp/go-cache",
		"-v", workspaceMount,
		"-w", workspaceDir,
	}
	cmd := "go mod tidy && go build -o /tmp/agent ."
	// Dev: mount the local lib proxy and point GOPROXY at it (public proxy
	// second). The proxy serves each owned lib at a content-addressed
	// version, so changed source is a new version — Go fetches it fresh with
	// no cache eviction needed.
	if proxyDir != "" {
		args = append(args, "-v", proxyDir+":/goproxy:ro",
			"-e", "GOPROXY=file:///goproxy,https://proxy.golang.org")
	}
	args = append(args, b.cfg.AgentBuilderImage, "sh", "-c", cmd)

	dcmd := exec.CommandContext(ctx, "docker", args...)
	out, err := dcmd.CombinedOutput()
	if err != nil {
		b.logger.Warn("warm runtime caches: docker run failed", zap.String("output", string(out)), zap.Error(err))
		return
	}

	b.logger.Info("runtime caches warmed")
}

// runAndStream runs a command and streams its combined output line by line via logFn.
// On failure, the error includes the last few lines of output for diagnostics.
func runAndStream(cmd *exec.Cmd, logFn func(string)) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // merge stderr into stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	// Keep a rolling buffer of the last N lines for error reporting.
	const tailSize = 20
	tail := make([]string, 0, tailSize)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		logFn(line)
		if len(tail) >= tailSize {
			tail = tail[1:]
		}
		tail = append(tail, line)
	}
	// Drain any remaining data
	io.Copy(io.Discard, stdout)

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("docker build: %s: %w", strings.Join(tail, "\n"), err)
	}
	return nil
}
