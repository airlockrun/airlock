package builder

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/scaffold"
	"github.com/airlockrun/goai"
	"github.com/airlockrun/sol"
)

// HousekeepingResult reports what runHousekeeping changed in the agent repo
// so the caller can decide whether to make a chore commit.
type HousekeepingResult struct {
	DockerfileChanged bool
	GitignoreChanged  bool
	GoModChanged      bool
}

// Changed returns true if any airlock-managed file was rewritten.
func (r HousekeepingResult) Changed() bool {
	return r.DockerfileChanged || r.GitignoreChanged || r.GoModChanged
}

// gitignoreManagedLines are the entries airlock requires in every agent's
// .gitignore so its build-time go.work pair (written into the working tree
// per build) doesn't get accidentally committed.
var gitignoreManagedLines = []string{"go.work", "go.work.sum"}

// libRequires maps the airlock-managed module path to its currently-compiled
// version. These are the only require lines airlock touches in an agent's
// go.mod — everything else is user-owned. Read from the lib's compiled-in
// const so airlock and the agent always agree on what version is shipping.
func libRequires() map[string]string {
	return map[string]string{
		"github.com/airlockrun/agentsdk": "v" + agentsdk.Version,
		"github.com/airlockrun/goai":     "v" + goai.Version,
		"github.com/airlockrun/sol":      "v" + sol.Version,
	}
}

// runHousekeeping rewrites the airlock-managed files in repoPath to match
// the current airlock binary's idea of canonical state:
//   - Dockerfile: regenerated from scaffold/templates/Dockerfile.tmpl
//   - .gitignore: airlock-required entries (go.work, go.work.sum) appended
//     if absent; user's other entries untouched
//   - go.mod: require lines for agentsdk/goai/sol pinned to the const
//     versions IFF they're already listed (don't add to non-importing agents)
//
// The working tree is mutated in place. The caller is responsible for
// committing the changes (read HousekeepingResult.Changed and run a chore
// commit if true) and for not interleaving other writes.
//
// Skipped silently when the agent repo doesn't have a go.mod yet (Build
// kind during initial scaffold — the scaffold itself writes canonical state
// so housekeeping has nothing to do).
func runHousekeeping(ctx context.Context, repoPath string, data scaffold.ScaffoldData) (HousekeepingResult, error) {
	var res HousekeepingResult

	goModPath := filepath.Join(repoPath, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return res, nil
		}
		return res, fmt.Errorf("stat go.mod: %w", err)
	}

	dockerfileChanged, err := rewriteDockerfile(repoPath, data)
	if err != nil {
		return res, fmt.Errorf("rewrite Dockerfile: %w", err)
	}
	res.DockerfileChanged = dockerfileChanged

	gitignoreChanged, err := ensureGitignoreEntries(repoPath, gitignoreManagedLines)
	if err != nil {
		return res, fmt.Errorf("update .gitignore: %w", err)
	}
	res.GitignoreChanged = gitignoreChanged

	goModChanged, err := refreshLibRequires(ctx, repoPath, libRequires())
	if err != nil {
		return res, fmt.Errorf("refresh go.mod requires: %w", err)
	}
	res.GoModChanged = goModChanged

	return res, nil
}

// rewriteDockerfile renders the scaffold Dockerfile template into repoPath
// and reports whether the file content actually changed. A no-op write
// (content matches existing) returns false so the caller can skip the chore
// commit. data must carry GoVersion / AgentSDKVersion / AgentBaseImage —
// scaffold.GenerateDockerfile validates the latter two.
func rewriteDockerfile(repoPath string, data scaffold.ScaffoldData) (bool, error) {
	target := filepath.Join(repoPath, "Dockerfile")
	before, _ := os.ReadFile(target) // missing-file returns nil, fine
	if err := scaffold.GenerateDockerfile(repoPath, data); err != nil {
		return false, err
	}
	after, err := os.ReadFile(target)
	if err != nil {
		return false, err
	}
	return string(before) != string(after), nil
}

// ensureGitignoreEntries appends any of `lines` that aren't already present
// in repoPath/.gitignore. Comparison is line-equality (whitespace-trimmed)
// so a re-ordered file or surrounding comments don't trigger spurious
// rewrites. Creates the file if missing.
func ensureGitignoreEntries(repoPath string, lines []string) (bool, error) {
	target := filepath.Join(repoPath, ".gitignore")
	raw, err := os.ReadFile(target)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	existing := map[string]struct{}{}
	for _, l := range strings.Split(string(raw), "\n") {
		existing[strings.TrimSpace(l)] = struct{}{}
	}
	var toAppend []string
	for _, l := range lines {
		if _, ok := existing[l]; !ok {
			toAppend = append(toAppend, l)
		}
	}
	if len(toAppend) == 0 {
		return false, nil
	}
	var b strings.Builder
	b.Write(raw)
	// Make sure the existing content ends with a newline before our
	// appended block so the new entries land on their own lines.
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		b.WriteByte('\n')
	}
	for _, l := range toAppend {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(target, []byte(b.String()), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// refreshLibRequires pins each managed module to the given version IFF that
// module already appears in go.mod's require list. New modules are never
// added — an agent that doesn't import a lib must not gain a dangling
// require for it. Returns whether go.mod changed.
//
// Uses `go mod edit -require=mod@ver`, which is format-preserving and
// idempotent (already-correct version → no change).
func refreshLibRequires(ctx context.Context, repoPath string, want map[string]string) (bool, error) {
	goModPath := filepath.Join(repoPath, "go.mod")
	before, err := os.ReadFile(goModPath)
	if err != nil {
		return false, err
	}
	beforeStr := string(before)
	for mod, ver := range want {
		// Match the module path as a whole token to avoid a partial
		// prefix match (e.g. agentsdk-foo containing agentsdk).
		if !strings.Contains(beforeStr, mod+" ") && !strings.Contains(beforeStr, "\t"+mod+" ") {
			continue
		}
		if err := runGoMod(ctx, repoPath, "edit", "-require="+mod+"@"+ver); err != nil {
			return false, fmt.Errorf("go mod edit -require=%s@%s: %w", mod, ver, err)
		}
	}
	after, err := os.ReadFile(goModPath)
	if err != nil {
		return false, err
	}
	return string(before) != string(after), nil
}

// commitHousekeeping stages the airlock-managed files that runHousekeeping
// rewrote and creates a single chore commit. Only the files that actually
// changed are staged — we never `git add -A`, because the user may have
// uncommitted edits to their own code that we must not pull in here.
//
// Authors as Airlock so a `git log --author` filter trivially separates
// airlock-authored commits from sol-authored and user-authored ones.
func commitHousekeeping(repoPath string, r HousekeepingResult) error {
	var paths []string
	if r.DockerfileChanged {
		paths = append(paths, "Dockerfile")
	}
	if r.GitignoreChanged {
		paths = append(paths, ".gitignore")
	}
	if r.GoModChanged {
		paths = append(paths, "go.mod")
	}
	if len(paths) == 0 {
		return nil
	}
	if err := git(repoPath, append([]string{"add", "--"}, paths...)...); err != nil {
		return fmt.Errorf("git add: %w", err)
	}
	msg := "chore: airlock housekeeping (" + strings.Join(paths, ", ") + ")"
	if err := git(repoPath, "commit",
		"--author=Airlock <airlock@localhost>",
		"-m", msg); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	return nil
}

// runGoMod runs `go mod <args...>` in dir with a clean git environment
// (otherwise a parent-shell GIT_INDEX_FILE poisons any git invocations
// `go mod` makes — same gotcha as runGit). Non-zero exit returns the
// combined output as the error message so callers can surface it.
func runGoMod(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "go", append([]string{"mod"}, args...)...)
	cmd.Dir = dir
	cmd.Env = gitCleanEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
