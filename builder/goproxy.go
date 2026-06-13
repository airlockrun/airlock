package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/goai"
	"github.com/airlockrun/sol"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"
)

// buildGoVersion is the Go toolchain version stamped into scaffolded
// agents' go.mod `go` directive and the Dockerfile `FROM golang:` tag.
// 3-component form matches what `go mod tidy` rewrites the directive to on
// Go 1.21+, so go.work/go.mod version checks don't trip.
const buildGoVersion = "1.26.0"

// libProxyMod describes one airlock-owned lib served by the dev-only local
// module proxy: the module path agents import, the subdirectory under
// AGENT_LIBS_PATH holding its source, and its const Version (source of
// truth; the latest git tag lags it during an rc cycle).
//
// Only the owned libs (agentsdk/goai/sol) need the local proxy. goose/templ
// are published modules and resolve from the public proxy like any other
// dependency.
type libProxyMod struct {
	path string
	sub  string
	cnst string // const Version, no leading "v"
}

// proxiedLibs lists the proxied libs in dependency order (goai → sol →
// agentsdk) so dev-version hashing can fold each lib's already-computed
// dependency versions into the one above it.
func proxiedLibs() []libProxyMod {
	return []libProxyMod{
		{"github.com/airlockrun/goai", "goai", goai.Version},
		{"github.com/airlockrun/sol", "sol", sol.Version},
		{"github.com/airlockrun/agentsdk", "agentsdk", agentsdk.Version},
	}
}

// computeDevVersions returns the content-addressed version the dev proxy
// serves each owned lib at: v<const>-dev<hash>, where the hash folds in the
// lib's own source plus the dev versions of the libs it depends on. Any edit
// to a lib — or to anything it transitively requires — yields a fresh, unique
// version. Go's module cache keys by version, so a new version is a new
// immutable cache entry: no eviction to manage, and concurrent builds sharing
// the cache never race on a mutated entry. Dependency order guarantees a
// lib's dependencies are hashed before it.
func computeDevVersions(libsPath string) (map[string]string, error) {
	versions := map[string]string{}
	for _, m := range proxiedLibs() {
		// Fold in every dep version computed so far (dependency order) so an
		// upstream edit cascades into this lib's version too — which keeps the
		// version in lockstep with the rewritten inter-lib requires the proxy
		// bakes into this lib's served go.mod.
		var deps []string
		for _, d := range proxiedLibs() {
			if v, ok := versions[d.path]; ok {
				deps = append(deps, d.path+"@"+v)
			}
		}
		h, err := hashTree(filepath.Join(libsPath, m.sub), deps...)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", m.path, err)
		}
		// "-dev"+hex is a single, always-alphanumeric prerelease identifier
		// (it contains letters), so it's valid semver regardless of the hash.
		versions[m.path] = "v" + m.cnst + "-dev" + h
	}
	return versions, nil
}

// hashTree returns a short hex digest over all regular files under dir
// (excluding .git and vendor, matching what the module zip carries), plus any
// extra strings folded in. Deterministic: entries are sorted by path and the
// content is hashed, so identical source yields an identical digest.
func hashTree(dir string, extra ...string) (string, error) {
	type entry struct {
		rel  string
		data []byte
	}
	var entries []entry
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel == ".git" || rel == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{filepath.ToSlash(rel), b})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "%s\x00%d\x00", e.rel, len(e.data))
		h.Write(e.data)
	}
	for _, s := range extra {
		fmt.Fprintf(h, "%s\x00", s)
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

// agentSDKVersion is the version the agent's go.mod pins for agentsdk and
// that the proxy serves it at. Dev (AGENT_LIBS_PATH set): the content-
// addressed v<const>-dev<hash> so live lib edits resolve fresh. Prod: the
// published v<const>.
func (b *BuildService) agentSDKVersion() (string, error) {
	if !b.cfg.AgentLibsPathExplicit {
		return "v" + agentsdk.Version, nil
	}
	versions, err := computeDevVersions(b.cfg.AgentLibsPath)
	if err != nil {
		return "", err
	}
	v, ok := versions["github.com/airlockrun/agentsdk"]
	if !ok {
		return "", errors.New("agentSDKVersion: agentsdk missing from computed dev versions")
	}
	return v, nil
}

// devGoProxy is the GOPROXY value used by dev builds: the local file proxy
// first (serves the owned libs at their pinned versions from live source),
// falling through to the public proxy for everything else.
func devGoProxy(proxyDir string) string {
	return "file://" + filepath.ToSlash(proxyDir) + ",https://proxy.golang.org"
}

// generateLibProxy writes a Go module proxy at proxyDir serving each owned
// lib's live source (under libsPath) as its pinned version. The layout
// matches the GOPROXY file:// protocol:
//
//	<proxyDir>/<escaped-module>/@v/list
//	<proxyDir>/<escaped-module>/@v/<version>.info
//	<proxyDir>/<escaped-module>/@v/<version>.mod
//	<proxyDir>/<escaped-module>/@v/<version>.zip
//
// Regenerated per build so live edits to the lib source are reflected
// without retagging. Uses golang.org/x/mod/zip (a library — no `go`
// toolchain needed, which matters because airlock's prod container ships
// only the airlock binary; this path is dev-only regardless).
func generateLibProxy(proxyDir, libsPath string) error {
	// Content-addressed versions the proxy serves, keyed by module path. Also
	// used to rewrite each lib's inter-lib require lines so the module graph
	// selects the proxy's local versions instead of falling through to the
	// published (older) versions the lib repos' go.mod files actually pin.
	wantVersions, err := computeDevVersions(libsPath)
	if err != nil {
		return fmt.Errorf("compute dev versions: %w", err)
	}

	for _, m := range proxiedLibs() {
		version := wantVersions[m.path]
		srcDir := filepath.Join(libsPath, m.sub)
		if _, err := os.Stat(filepath.Join(srcDir, "go.mod")); err != nil {
			return fmt.Errorf("lib %s: no go.mod at %s: %w", m.path, srcDir, err)
		}

		// Stage a copy of the source (minus .git) so we can rewrite go.mod
		// without touching the live tree. The rewritten go.mod becomes both
		// the served .mod and the zip's go.mod — they must agree.
		stage, err := os.MkdirTemp("", "airlock-libstage-*")
		if err != nil {
			return fmt.Errorf("stage dir for %s: %w", m.path, err)
		}
		if err := copyModuleSource(srcDir, stage); err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("stage %s: %w", m.path, err)
		}
		if err := rewriteInterLibRequires(filepath.Join(stage, "go.mod"), m.path, wantVersions); err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("rewrite go.mod for %s: %w", m.path, err)
		}

		escaped, err := module.EscapePath(m.path)
		if err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("escape module path %s: %w", m.path, err)
		}
		vdir := filepath.Join(proxyDir, filepath.FromSlash(escaped), "@v")
		if err := os.MkdirAll(vdir, 0o755); err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("mkdir %s: %w", vdir, err)
		}

		// .info — minimal version metadata.
		info, err := json.Marshal(struct {
			Version string
			Time    time.Time
		}{version, time.Now().UTC()})
		if err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("marshal info for %s: %w", m.path, err)
		}
		if err := os.WriteFile(filepath.Join(vdir, version+".info"), info, 0o644); err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("write info for %s: %w", m.path, err)
		}

		// .mod — the rewritten go.mod from the stage.
		gomod, err := os.ReadFile(filepath.Join(stage, "go.mod"))
		if err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("read staged go.mod for %s: %w", m.path, err)
		}
		if err := os.WriteFile(filepath.Join(vdir, version+".mod"), gomod, 0o644); err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("write mod for %s: %w", m.path, err)
		}

		// .zip — the staged module source (carrying the same rewritten go.mod).
		zf, err := os.Create(filepath.Join(vdir, version+".zip"))
		if err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("create zip for %s: %w", m.path, err)
		}
		err = zip.CreateFromDir(zf, module.Version{Path: m.path, Version: version}, stage)
		closeErr := zf.Close()
		os.RemoveAll(stage)
		if err != nil {
			return fmt.Errorf("zip %s: %w", m.path, err)
		}
		if closeErr != nil {
			return fmt.Errorf("close zip for %s: %w", m.path, closeErr)
		}

		// list — the available versions (just the one we serve).
		if err := os.WriteFile(filepath.Join(vdir, "list"), []byte(version+"\n"), 0o644); err != nil {
			return fmt.Errorf("write list for %s: %w", m.path, err)
		}
	}
	return nil
}

// rewriteInterLibRequires updates the require lines in the go.mod at
// modPath so each *other* owned lib is pinned to the version the proxy
// serves. Only modules already required are touched — no new requires are
// added. self is skipped. Uses x/mod/modfile (a library, no toolchain).
func rewriteInterLibRequires(goModPath, self string, want map[string]string) error {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return err
	}
	mf, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return fmt.Errorf("parse go.mod: %w", err)
	}
	required := map[string]bool{}
	for _, r := range mf.Require {
		required[r.Mod.Path] = true
	}
	changed := false
	for path, ver := range want {
		if path == self || !required[path] {
			continue
		}
		if err := mf.AddRequire(path, ver); err != nil {
			return fmt.Errorf("set require %s@%s: %w", path, ver, err)
		}
		changed = true
	}
	if !changed {
		return nil
	}
	mf.Cleanup()
	out, err := mf.Format()
	if err != nil {
		return fmt.Errorf("format go.mod: %w", err)
	}
	return os.WriteFile(goModPath, out, 0o644)
}

// copyModuleSource recursively copies srcDir to dstDir, skipping VCS and
// vendor directories. Regular files only — symlinks and special files are
// skipped (module zips don't carry them anyway).
func copyModuleSource(srcDir, dstDir string) error {
	return filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel == ".git" || rel == "vendor" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dstDir, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return copyFile(path, filepath.Join(dstDir, rel))
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ensureLibProxy generates a fresh dev lib proxy and returns its directory
// plus a cleanup func. In prod (AGENT_LIBS_PATH not explicitly set) it's a
// no-op: returns an empty dir, a no-op cleanup, and nil error, so callers
// uniformly do `if dir != "" { … wire GOPROXY … }`.
func (b *BuildService) ensureLibProxy() (dir string, cleanup func(), err error) {
	cleanup = func() {}
	if !b.cfg.AgentLibsPathExplicit {
		return "", cleanup, nil
	}
	if b.cfg.AgentLibsPath == "" {
		return "", cleanup, fmt.Errorf("ensureLibProxy: AGENT_LIBS_PATH explicit but AgentLibsPath empty")
	}
	dir, err = b.makeCodegenTempDir("airlock-goproxy-*")
	if err != nil {
		return "", cleanup, fmt.Errorf("create proxy dir: %w", err)
	}
	if err := generateLibProxy(dir, b.cfg.AgentLibsPath); err != nil {
		os.RemoveAll(dir)
		return "", cleanup, err
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}
