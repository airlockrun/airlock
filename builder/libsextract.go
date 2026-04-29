package builder

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// ownedLibs are libs we control + edit (overlay-able from AGENT_LIBS_PATH).
var ownedLibs = []string{"agentsdk", "goai", "sol"}

// externalLibs are third-party libs always sourced from the agent-builder
// image — devs don't edit them, so no overlay path.
var externalLibs = []string{"goose", "templ"}

// LibsPaths is what callers need to wire up the per-agent docker build's
// two BuildKit contexts (libs-owned + libs-ext) and the toolserver's
// bind-mount overlay (Owned).
type LibsPaths struct {
	// Owned is the directory containing agentsdk/goai/sol. Either the
	// operator's AGENT_LIBS_PATH (live dev source) or the extracted cache.
	Owned string
	// Ext is the directory containing goose/templ. Always the extracted
	// cache (devs don't edit these).
	Ext string
}

// EnsureLibs guarantees that:
//   - The agent-builder image's full /libs/* set is materialized on the host
//     under <cacheDir>/<image-id>/, cached by image ID so a tag bump triggers
//     re-extraction.
//   - If explicitPath (AGENT_LIBS_PATH) is set, the owned subdirs all exist
//     there. Owned then points at explicitPath; Ext at the cache.
//   - If explicitPath is empty (prod), both Owned and Ext point at the cache.
func EnsureLibs(ctx context.Context, image, explicitPath, cacheDir string, logger *zap.Logger) (LibsPaths, error) {
	if image == "" {
		return LibsPaths{}, fmt.Errorf("EnsureLibs: AGENT_BUILDER_IMAGE is empty")
	}
	if cacheDir == "" {
		return LibsPaths{}, fmt.Errorf("EnsureLibs: AGENT_LIBS_CACHE_DIR is empty")
	}

	extracted, err := extractFromImage(ctx, image, cacheDir, logger)
	if err != nil {
		return LibsPaths{}, err
	}

	if explicitPath == "" {
		return LibsPaths{Owned: extracted, Ext: extracted}, nil
	}

	for _, sub := range ownedLibs {
		p := filepath.Join(explicitPath, sub)
		if _, err := os.Stat(p); err != nil {
			return LibsPaths{}, fmt.Errorf("AGENT_LIBS_PATH=%s missing %s: %w", explicitPath, sub, err)
		}
	}
	logger.Info("agent libs: dev overlay active",
		zap.String("owned", explicitPath),
		zap.String("ext", extracted))
	return LibsPaths{Owned: explicitPath, Ext: extracted}, nil
}

// extractFromImage pulls the agent-builder image (if missing) and extracts
// /libs/{ownedLibs..., externalLibs...} into <cacheDir>/<image-id>/. Cached
// by image ID with a .extracted marker.
func extractFromImage(ctx context.Context, image, cacheDir string, logger *zap.Logger) (string, error) {
	if err := dockerImageExists(ctx, image); err != nil {
		// Pull only if missing — pulling an existing tagged image would
		// re-fetch on registry pushes, which we don't want for pinned tags.
		logger.Info("agent libs: pulling agent-builder image", zap.String("image", image))
		out, err := exec.CommandContext(ctx, "docker", "pull", image).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("docker pull %s: %s: %w", image, strings.TrimSpace(string(out)), err)
		}
	}

	id, err := dockerImageID(ctx, image)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(cacheDir, id)

	if extractionComplete(dest) {
		logger.Info("agent libs: using cached extraction", zap.String("path", dest))
		return dest, nil
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dest, err)
	}

	cid, err := dockerCreate(ctx, image)
	if err != nil {
		return "", err
	}
	defer func() {
		if out, err := exec.CommandContext(context.Background(), "docker", "rm", "-f", cid).CombinedOutput(); err != nil {
			logger.Warn("agent libs: failed to remove temp container",
				zap.String("container", cid),
				zap.String("output", strings.TrimSpace(string(out))),
				zap.Error(err))
		}
	}()

	for _, sub := range allLibs() {
		src := cid + ":/libs/" + sub
		out, err := exec.CommandContext(ctx, "docker", "cp", src, dest).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("docker cp %s: %s: %w", src, strings.TrimSpace(string(out)), err)
		}
	}

	if err := os.WriteFile(filepath.Join(dest, ".extracted"), []byte(image+"\n"+id+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write extraction marker: %w", err)
	}

	logger.Info("agent libs: extracted",
		zap.String("image", image),
		zap.String("path", dest))
	return dest, nil
}

func dockerImageExists(ctx context.Context, image string) error {
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect", image, "--format", "{{.Id}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect %s: %s: %w", image, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func dockerImageID(ctx context.Context, image string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect", image, "--format", "{{.Id}}").Output()
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", image, err)
	}
	id := strings.TrimSpace(string(out))
	id = strings.TrimPrefix(id, "sha256:")
	if id == "" {
		return "", fmt.Errorf("empty image ID for %s", image)
	}
	return id, nil
}

func dockerCreate(ctx context.Context, image string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "create", image).Output()
	if err != nil {
		return "", fmt.Errorf("docker create %s: %w", image, err)
	}
	cid := strings.TrimSpace(string(out))
	if cid == "" {
		return "", fmt.Errorf("docker create returned empty container ID for %s", image)
	}
	return cid, nil
}

func extractionComplete(dest string) bool {
	if _, err := os.Stat(filepath.Join(dest, ".extracted")); err != nil {
		return false
	}
	for _, sub := range allLibs() {
		if _, err := os.Stat(filepath.Join(dest, sub)); err != nil {
			return false
		}
	}
	return true
}

func allLibs() []string {
	out := make([]string, 0, len(ownedLibs)+len(externalLibs))
	out = append(out, ownedLibs...)
	out = append(out, externalLibs...)
	return out
}
