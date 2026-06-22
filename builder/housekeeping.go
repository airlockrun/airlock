package builder

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/airlockrun/airlock/scaffold"
)

// HousekeepingResult reports what runHousekeeping changed in the agent repo
// so the caller can decide whether to make a chore commit.
type HousekeepingResult struct {
	DockerfileChanged bool
	AgentsMDChanged   bool
	GitignoreChanged  bool
	GoModChanged      bool
	NoticesChanged    bool
}

// Changed returns true if any airlock-managed file was rewritten.
func (r HousekeepingResult) Changed() bool {
	return r.DockerfileChanged || r.AgentsMDChanged || r.GitignoreChanged || r.GoModChanged || r.NoticesChanged
}

// gitignoreManagedLines are the entries airlock keeps in every agent's
// .gitignore. A dev cloning the repo may create a local go.work for their
// own multi-module setup; keeping it ignored stops it leaking into a push.
var gitignoreManagedLines = []string{"go.work", "go.work.sum"}

// runHousekeeping rewrites the airlock-managed files in repoPath to match
// the current airlock binary's idea of canonical state:
//   - Dockerfile: regenerated from scaffold/templates/Dockerfile.tmpl
//   - AGENTS.md: regenerated from scaffold/templates/AGENTS.md.tmpl —
//     airlock-managed doc, overwritten so agents pick up doc updates
//   - .gitignore: airlock-kept entries appended if absent; user's other
//     entries untouched
//   - THIRD_PARTY_NOTICES.generated.md: airlock-owned dependency notices,
//     overwritten from the embedded template so the bundled licenses stay
//     current. Distinct from the conventional THIRD_PARTY_NOTICES.md, which is
//     left for the user's own notices.
//   - go.mod: the agentsdk `require` pinned to data.AgentSDKVersion — the
//     published v<const> in prod, the content-addressed v<const>-dev<hash>
//     in dev (regex edit — agentsdk is the only owned lib the agent requires
//     directly; goai/sol are indirect and resolved by `go mod tidy` via the
//     build's module proxy). No `go mod edit` shell-out, so this works in
//     the prod airlock container which has no Go toolchain.
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

	// Remove any stale go.work from the working tree. It's gitignored, so
	// it never gets committed — but the Dockerfile's `COPY . .` would copy
	// it into the build context, and `go mod tidy` honors its /libs
	// replaces (which no longer exist), failing the build. Airlock doesn't
	// write go.work anymore; this clears leftovers from older builds.
	for _, f := range []string{"go.work", "go.work.sum"} {
		if err := os.Remove(filepath.Join(repoPath, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return res, fmt.Errorf("remove stale %s: %w", f, err)
		}
	}

	dockerfileChanged, err := rewriteDockerfile(repoPath, data)
	if err != nil {
		return res, fmt.Errorf("rewrite Dockerfile: %w", err)
	}
	res.DockerfileChanged = dockerfileChanged

	agentsMDChanged, err := rewriteAgentsMD(repoPath, data)
	if err != nil {
		return res, fmt.Errorf("rewrite AGENTS.md: %w", err)
	}
	res.AgentsMDChanged = agentsMDChanged

	gitignoreChanged, err := reconcileGitignore(repoPath, gitignoreManagedLines, gitignoreRemoveLines)
	if err != nil {
		return res, fmt.Errorf("update .gitignore: %w", err)
	}
	res.GitignoreChanged = gitignoreChanged

	noticesChanged, err := rewriteNotices(repoPath)
	if err != nil {
		return res, fmt.Errorf("rewrite notices: %w", err)
	}
	res.NoticesChanged = noticesChanged

	before, err := os.ReadFile(goModPath)
	if err != nil {
		return res, fmt.Errorf("read go.mod: %w", err)
	}
	if err := bumpAgentSDKRequire(ctx, repoPath, data.AgentSDKVersion); err != nil {
		return res, fmt.Errorf("bump agentsdk require: %w", err)
	}
	after, err := os.ReadFile(goModPath)
	if err != nil {
		return res, fmt.Errorf("read go.mod: %w", err)
	}
	res.GoModChanged = string(before) != string(after)

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

// rewriteAgentsMD renders the scaffold AGENTS.md template into repoPath and
// reports whether the file content actually changed. AGENTS.md is
// airlock-managed (not agent-owned), so housekeeping overwrites it to the
// current template — the same overwrite-and-diff contract as the Dockerfile.
// A no-op write returns false so the caller can skip the chore commit.
func rewriteAgentsMD(repoPath string, data scaffold.ScaffoldData) (bool, error) {
	target := filepath.Join(repoPath, "AGENTS.md")
	before, _ := os.ReadFile(target) // missing-file returns nil, fine
	if err := scaffold.GenerateAgentsMD(repoPath, data); err != nil {
		return false, err
	}
	after, err := os.ReadFile(target)
	if err != nil {
		return false, err
	}
	return string(before) != string(after), nil
}

// rewriteNotices copies the airlock-owned third-party notices into repoPath and
// reports whether the content changed. The file is airlock-managed (generated
// from the dep graph, embedded in the binary), so housekeeping overwrites it to
// the current template — the same overwrite-and-diff contract as the
// Dockerfile. Its name (THIRD_PARTY_NOTICES.generated.md) is distinct from the
// conventional THIRD_PARTY_NOTICES.md, so a user's own notices are never
// touched. A no-op write returns false so the caller can skip the chore commit.
func rewriteNotices(repoPath string) (bool, error) {
	target := filepath.Join(repoPath, scaffold.NoticesFilename)
	before, _ := os.ReadFile(target) // missing-file returns nil, fine
	if err := scaffold.GenerateNotices(repoPath); err != nil {
		return false, err
	}
	after, err := os.ReadFile(target)
	if err != nil {
		return false, err
	}
	return string(before) != string(after), nil
}

// gitignoreRemoveLines are entries airlock must strip from .gitignore.
// Dockerfile is committed (so users can `docker build .` locally); an old
// .gitignore listing it would block airlock from committing the
// regenerated Dockerfile (`git add` refuses an ignored path).
var gitignoreRemoveLines = []string{"Dockerfile"}

// reconcileGitignore makes .gitignore carry airlock's managed entries and
// none of its forbidden ones: appends `add` lines that are absent, drops any
// line matching `remove`. User-authored lines are preserved in place.
// Comparison is whitespace-trimmed. Creates the file if missing. Returns
// whether the file changed.
func reconcileGitignore(repoPath string, add, remove []string) (bool, error) {
	target := filepath.Join(repoPath, ".gitignore")
	raw, err := os.ReadFile(target)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	removeSet := map[string]struct{}{}
	for _, l := range remove {
		removeSet[l] = struct{}{}
	}

	// Preserve the original line structure minus a trailing empty element
	// from a final newline (re-added on write). Drop forbidden lines.
	lines := strings.Split(string(raw), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	present := map[string]struct{}{}
	kept := make([]string, 0, len(lines))
	changed := false
	for _, l := range lines {
		if _, drop := removeSet[strings.TrimSpace(l)]; drop {
			changed = true
			continue
		}
		kept = append(kept, l)
		present[strings.TrimSpace(l)] = struct{}{}
	}
	for _, l := range add {
		if _, ok := present[l]; !ok {
			kept = append(kept, l)
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	out := strings.Join(kept, "\n") + "\n"
	if err := os.WriteFile(target, []byte(out), 0o644); err != nil {
		return false, err
	}
	return true, nil
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
	if r.AgentsMDChanged {
		paths = append(paths, "AGENTS.md")
	}
	if r.GitignoreChanged {
		paths = append(paths, ".gitignore")
	}
	if r.NoticesChanged {
		paths = append(paths, scaffold.NoticesFilename)
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
