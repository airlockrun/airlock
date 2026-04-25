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

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/scaffold"
	"go.uber.org/zap"
)

// buildImage builds a Docker image from the agent's directory.
// If logFn is non-nil, Docker build output is streamed line by line.
// Returns the image tag.
func buildImage(ctx context.Context, cfg *config.Config, agentID, contextDir, commitHash string, logFn func(string)) (string, error) {
	tag := fmt.Sprintf("%s:%s", agentID, commitHash[:12])
	if cfg.AgentRegistryURL != "" {
		tag = fmt.Sprintf("%s/%s", cfg.AgentRegistryURL, tag)
	}

	if cfg.AgentLibsPath == "" || cfg.AgentLibsExtPath == "" {
		return "", fmt.Errorf("buildImage: AgentLibsPath/AgentLibsExtPath empty — startup should have populated both via EnsureLibs")
	}
	args := []string{
		"build", "-t", tag,
		"--build-context", "libs-owned=" + cfg.AgentLibsPath,
		"--build-context", "libs-ext=" + cfg.AgentLibsExtPath,
		contextDir,
	}

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

// WarmBuildCache pre-downloads Go module dependencies so that the first real
// agent build hits a warm cache. Materializes a real scaffold and runs a full
// docker build (same Dockerfile.tmpl + go.mod.tmpl as real builds), then
// removes the throwaway image. The cache mounts persist.
func (b *BuildService) WarmBuildCache(ctx context.Context) {
	dir, err := os.MkdirTemp("", "airlock-cache-warm-*")
	if err != nil {
		b.logger.Warn("warm cache: create temp dir", zap.Error(err))
		return
	}
	defer os.RemoveAll(dir)

	// Materialize a real scaffold — same templates as actual agent builds.
	if err := scaffold.Materialize(dir, scaffold.ScaffoldData{
		AgentID:   "cache-warm",
		Module:    "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v" + agentsdk.Version,
	}); err != nil {
		b.logger.Warn("warm cache: scaffold", zap.Error(err))
		return
	}

	// Generate Dockerfile from current template (not part of scaffold anymore).
	if err := scaffold.GenerateDockerfile(dir, scaffold.ScaffoldData{
		AgentID:   "cache-warm",
		Module:    "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v" + agentsdk.Version,
	}); err != nil {
		b.logger.Warn("warm cache: generate Dockerfile", zap.Error(err))
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

	if b.cfg.AgentLibsPath == "" || b.cfg.AgentLibsExtPath == "" {
		b.logger.Warn("warm cache: lib paths empty — skipping (startup EnsureLibs must run first)")
		return
	}
	tag := "airlock-cache-warm:latest"
	args := []string{
		"build", "-t", tag,
		"--build-context", "libs-owned=" + b.cfg.AgentLibsPath,
		"--build-context", "libs-ext=" + b.cfg.AgentLibsExtPath,
		dir,
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(cmd.Environ(), "DOCKER_BUILDKIT=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		b.logger.Warn("warm cache: docker build failed", zap.String("output", string(out)), zap.Error(err))
		return
	}

	// Remove throwaway image — the cache mounts persist.
	_ = exec.CommandContext(ctx, "docker", "rmi", tag).Run()

	b.logger.Info("build cache warmed")
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
