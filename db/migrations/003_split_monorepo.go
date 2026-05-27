// Package migrations registers goose-driven schema and operational
// migrations. SQL files in this directory are picked up automatically by
// the embed.FS in db/migrate.go; Go migrations register themselves via
// init() calls on package import. db/migrate.go blank-imports this
// package so the init() side-effects run before goose.UpContext.
package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

func init() {
	// NoTx: this migration performs filesystem work (git operations,
	// directory renames, go.mod rewrites). Holding a Postgres transaction
	// across multi-second git invocations is a footgun; nothing in this
	// migration touches the DB anyway.
	goose.AddMigrationNoTxContext(upMigrate003, downMigrate003)
}

// upMigrate003 runs the two filesystem operations historically split
// across versions 3 and 5: convert any legacy monorepo into per-agent
// repos, then strip the airlock-managed /libs/... replace directives
// from each agent's committed go.mod. Both are idempotent — re-running
// is a no-op once everything is in the target shape.
func upMigrate003(ctx context.Context, db *sql.DB) error {
	if err := upSplitMonorepo(ctx, db); err != nil {
		return err
	}
	return upStripLibsReplaces(ctx, db)
}

func downMigrate003(ctx context.Context, db *sql.DB) error {
	return downSplitMonorepo(ctx, db)
}

// upSplitMonorepo converts the legacy single-monorepo layout
//
//	<oldPath>/.git
//	<oldPath>/agents/<id>/...
//
// into a per-agent-repo layout at the new location
//
//	<newPath>/<id>/.git
//	<newPath>/<id>/...
//
// using `git subtree split` per agent so each per-agent repo carries
// only its own history (no cross-agent commits leak). The legacy
// .git/ and agents/ in oldPath are moved aside into
// <oldPath>/_monorepo_archive/ rather than deleted, so an operator can
// recover manually if something went wrong.
//
// Paths: oldPath is read from AGENT_MONOREPO_PATH (default
// /var/lib/airlock/monorepo — the pre-multirepo location). newPath is
// read from AGENT_REPOS_PATH (default /var/lib/airlock/agents). When
// they happen to be the same directory the split is in-place; when they
// differ the per-agent repos land in newPath and oldPath is left
// holding only the archive.
//
// Idempotent in the common cases: a fresh install with no oldPath is a
// no-op; an agent already split (per-agent dir already exists in
// newPath) is skipped, not re-split.
//
// Forward-only — downSplitMonorepo is a no-op. Reconstructing a
// monorepo from per-agent repos would require merging unrelated
// histories with `git read-tree` magic that's not worth supporting; if
// you absolutely need the old layout back, restore _monorepo_archive/
// manually.
func upSplitMonorepo(ctx context.Context, _ *sql.DB) error {
	oldPath := legacyMonorepoPath()
	newPath := agentReposPath()

	monorepoGit := filepath.Join(oldPath, ".git")
	if _, err := os.Stat(monorepoGit); errors.Is(err, fs.ErrNotExist) {
		// Fresh install — no monorepo to split.
		return nil
	} else if err != nil {
		return fmt.Errorf("stat monorepo .git: %w", err)
	}

	if err := os.MkdirAll(newPath, 0o755); err != nil {
		return fmt.Errorf("mkdir new repos path: %w", err)
	}

	agentsDir := filepath.Join(oldPath, "agents")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// .git/ exists but no agents/ — likely a half-set-up install.
			// Just archive .git so future startups treat this as fresh.
			return archiveMonorepo(oldPath)
		}
		return fmt.Errorf("read monorepo agents/: %w", err)
	}

	var migrated, skipped []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		agentID := e.Name()
		if _, err := uuid.Parse(agentID); err != nil {
			skipped = append(skipped, agentID)
			continue
		}

		dst := filepath.Join(newPath, agentID)
		if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
			// Already split (re-run of this migration, or manual init).
			migrated = append(migrated, agentID+" (already present)")
			continue
		}

		if err := splitAgent(ctx, oldPath, agentID, dst); err != nil {
			return fmt.Errorf("split agent %s: %w", agentID, err)
		}
		migrated = append(migrated, agentID)
	}

	if err := archiveMonorepo(oldPath); err != nil {
		return fmt.Errorf("archive monorepo: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[migration 003] split %d agent(s) from %s into per-agent repos at %s\n",
		len(migrated), oldPath, newPath)
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "[migration 003] skipped non-UUID dirs: %v\n", skipped)
	}
	return nil
}

func downSplitMonorepo(_ context.Context, _ *sql.DB) error {
	return nil
}

// splitAgent extracts agents/<agentID>/ from the monorepo at basePath
// into a standalone repo at dst, preserving the history of paths under
// that prefix.
//
// Mechanism: `git subtree split --prefix=agents/<id> HEAD` writes a new
// commit chain whose tree contains only that subtree's files (with the
// prefix stripped). We then init dst as a fresh repo and fetch that
// commit chain in.
func splitAgent(ctx context.Context, basePath, agentID, dst string) error {
	splitOut, err := gitOutput(ctx, basePath, "subtree", "split",
		"--prefix=agents/"+agentID, "HEAD")
	if err != nil {
		return fmt.Errorf("subtree split: %w", err)
	}
	splitHash := strings.TrimSpace(splitOut)
	if splitHash == "" {
		return errors.New("subtree split produced no commit")
	}

	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dst, err)
	}
	if err := gitRun(ctx, dst, "init", "-b", "main"); err != nil {
		return fmt.Errorf("git init: %w", err)
	}
	// Fetch the split history from the monorepo. Source is a path, not a
	// URL, so file:// scheme isn't needed.
	if err := gitRun(ctx, dst, "fetch", basePath, splitHash); err != nil {
		return fmt.Errorf("fetch split: %w", err)
	}
	if err := gitRun(ctx, dst, "reset", "--hard", "FETCH_HEAD"); err != nil {
		return fmt.Errorf("reset --hard FETCH_HEAD: %w", err)
	}
	if err := gitRun(ctx, dst, "config", "user.email", "airlock@localhost"); err != nil {
		return fmt.Errorf("git config email: %w", err)
	}
	if err := gitRun(ctx, dst, "config", "user.name", "Airlock"); err != nil {
		return fmt.Errorf("git config name: %w", err)
	}
	// Match builder.InitAgentRepo so per-upgrade clones can push back.
	if err := gitRun(ctx, dst, "config", "receive.denyCurrentBranch", "updateInstead"); err != nil {
		return fmt.Errorf("git config receive: %w", err)
	}
	return nil
}

// archiveMonorepo moves the old monorepo's .git/ and agents/ into
// <basePath>/_monorepo_archive/ so a future startup doesn't re-trigger
// this migration and an operator can recover by hand if needed.
// Idempotent — missing source dirs are not an error.
func archiveMonorepo(basePath string) error {
	bak := filepath.Join(basePath, "_monorepo_archive")
	if err := os.MkdirAll(bak, 0o755); err != nil {
		return fmt.Errorf("mkdir archive: %w", err)
	}
	for _, name := range []string{".git", "agents"} {
		src := filepath.Join(basePath, name)
		if _, err := os.Stat(src); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		dst := filepath.Join(bak, name)
		// If something already exists at the destination (re-run after a
		// failed first attempt), leave it alone and let the operator
		// reconcile manually rather than risk overwriting recovery state.
		if _, err := os.Stat(dst); err == nil {
			fmt.Fprintf(os.Stderr, "[migration 003] %s already exists in archive; leaving %s in place\n", dst, src)
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("archive %s: %w", name, err)
		}
	}
	return nil
}

// agentReposPath mirrors config.New for AGENT_REPOS_PATH — the new
// per-agent-repo base directory. Re-resolved here (rather than threaded
// through context) to keep airlock/db free of any airlock/config import.
func agentReposPath() string {
	if v := os.Getenv("AGENT_REPOS_PATH"); v != "" {
		return v
	}
	return "/var/lib/airlock/agents"
}

// legacyMonorepoPath resolves the pre-multirepo location that a
// running install MIGHT still have a single monorepo at. Only this
// migration needs to know about it — config.go is past that name. If
// the operator never set AGENT_MONOREPO_PATH (the common case), this
// returns the historical default; the migration's first action is
// stat-checking for .git at that path and bailing fast when there's
// nothing to convert.
func legacyMonorepoPath() string {
	if v := os.Getenv("AGENT_MONOREPO_PATH"); v != "" {
		return v
	}
	return "/var/lib/airlock/monorepo"
}

func gitRun(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(gitCleanEnv(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(gitCleanEnv(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

// gitCleanEnv strips GIT_* vars from the inherited environment so a
// migration run from inside a git hook (e.g. a developer running airlock
// during a pre-commit) doesn't pick up the parent repo's GIT_INDEX_FILE.
func gitCleanEnv() []string {
	env := os.Environ()
	out := env[:0]
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			out = append(out, kv)
			continue
		}
		if strings.HasPrefix(kv[:eq], "GIT_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// upStripLibsReplaces walks every per-agent repo under AgentReposPath
// and strips the `replace github.com/airlockrun/... => /libs/...` block
// from each agent's committed `go.mod`, plus writes a `.gitignore` that
// covers airlock-managed files (Dockerfile, go.work, go.work.sum). Any
// changes are committed as a single per-agent chore commit. Pushes are
// NOT performed — the next user-or-codegen-triggered upgrade picks up
// these commits via the normal push path.
//
// Why: airlock injects a build-time `go.work` carrying the /libs/...
// replaces. Leaving them in the committed go.mod confuses user clones
// (`go build` fails locally because /libs/... doesn't exist on their
// laptop). The build-time go.work still works without these — it
// overrides go.mod replaces.
//
// Idempotent: an already-stripped repo produces no changes and no
// commit. Fresh install (no AgentReposPath) is a no-op. An agent with
// a dirty working tree is skipped with a warning rather than risk
// committing unrelated user changes.
func upStripLibsReplaces(ctx context.Context, _ *sql.DB) error {
	base := agentReposPath()
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // fresh install
		}
		return fmt.Errorf("read agent repos dir: %w", err)
	}

	var stripped, skippedDirty, skippedNonAgent []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if _, err := uuid.Parse(name); err != nil {
			continue // not an agent dir (e.g. _monorepo_archive)
		}
		dir := filepath.Join(base, name)
		if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
			skippedNonAgent = append(skippedNonAgent, name)
			continue
		}

		// Bail rather than risk committing in-flight user state. Allow
		// uncommitted airlock-managed files (Dockerfile, go.work,
		// go.work.sum) since the pre-cleanup build pipeline writes
		// those to the working tree without committing — cleanAgentRepo
		// will commit Dockerfile and gitignore go.work*.
		status, err := gitOutput(ctx, dir, "status", "--porcelain")
		if err != nil {
			return fmt.Errorf("git status %s: %w", name, err)
		}
		if dirtyBeyondManaged(status) {
			skippedDirty = append(skippedDirty, name)
			continue
		}

		changed, err := cleanAgentRepo(ctx, dir)
		if err != nil {
			return fmt.Errorf("clean %s: %w", name, err)
		}
		if changed {
			stripped = append(stripped, name)
		}
	}

	fmt.Fprintf(os.Stderr, "[migration 003] cleaned %d agent repo(s) under %s\n", len(stripped), base)
	if len(skippedDirty) > 0 {
		fmt.Fprintf(os.Stderr, "[migration 003] skipped dirty repos (uncommitted changes): %v\n", skippedDirty)
	}
	if len(skippedNonAgent) > 0 {
		fmt.Fprintf(os.Stderr, "[migration 003] skipped non-repo agent dirs: %v\n", skippedNonAgent)
	}
	return nil
}

// libsReplacedModules are the modules whose replace directives airlock
// historically wrote into the committed go.mod and now provides via
// build-time go.work instead.
var libsReplacedModules = []string{
	"github.com/airlockrun/agentsdk",
	"github.com/airlockrun/goai",
	"github.com/airlockrun/sol",
	"github.com/pressly/goose/v3",
	"github.com/a-h/templ",
}

// gitignoreContent mirrors scaffold/templates/gitignore.tmpl.
const gitignoreContent = `# Airlock-managed files — generated into the build context every build.
# Don't commit these; airlock will silently overwrite anything you do.
Dockerfile
go.work
go.work.sum
`

// cleanAgentRepo strips the /libs/... replaces from dir/go.mod, writes
// the canonical .gitignore, and stages any uncommitted Dockerfile from
// prior builds (Dockerfile is now committed so users can `docker build .`
// locally). Returns whether anything was committed.
func cleanAgentRepo(ctx context.Context, dir string) (bool, error) {
	goModPath := filepath.Join(dir, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		return false, nil // not a Go module; nothing to do
	}

	// `go mod edit -dropreplace` is the official, format-preserving way
	// to remove a single replace; idempotent for missing entries.
	for _, mod := range libsReplacedModules {
		if err := runCmd(ctx, dir, "go", "mod", "edit", "-dropreplace="+mod); err != nil {
			return false, fmt.Errorf("go mod edit -dropreplace=%s: %w", mod, err)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignoreContent), 0o644); err != nil {
		return false, fmt.Errorf("write .gitignore: %w", err)
	}

	status, err := gitOutput(ctx, dir, "status", "--porcelain")
	if err != nil {
		return false, fmt.Errorf("git status: %w", err)
	}
	if strings.TrimSpace(status) == "" {
		return false, nil // already clean
	}

	toStage := []string{"go.mod", ".gitignore"}
	if _, err := os.Stat(filepath.Join(dir, "Dockerfile")); err == nil {
		toStage = append(toStage, "Dockerfile")
	}
	if err := gitRun(ctx, dir, append([]string{"add"}, toStage...)...); err != nil {
		return false, fmt.Errorf("git add: %w", err)
	}
	if err := gitRun(ctx, dir, "commit",
		"--author=Airlock <airlock@localhost>",
		"-m", "chore: commit Dockerfile, drop /libs replaces, add .gitignore"); err != nil {
		return false, fmt.Errorf("git commit: %w", err)
	}
	return true, nil
}

// dirtyBeyondManaged returns true if `git status --porcelain` reports
// any file other than the airlock-managed Dockerfile/go.work/go.work.sum.
// Those three are expected to appear dirty on pre-migration repos —
// the migration commits Dockerfile and writes a .gitignore covering
// the go.work pair.
func dirtyBeyondManaged(status string) bool {
	managed := map[string]struct{}{
		"Dockerfile":  {},
		"go.work":     {},
		"go.work.sum": {},
	}
	for _, line := range strings.Split(status, "\n") {
		if len(line) < 3 {
			continue
		}
		// Porcelain format: "XY <path>" where X+Y are two status chars,
		// space, then the path. For untracked files X='?', Y='?'.
		path := strings.TrimSpace(line[3:])
		if path == "" {
			continue
		}
		if _, ok := managed[path]; !ok {
			return true
		}
	}
	return false
}

// runCmd runs a command with a clean git environment, returning a
// useful error on non-zero exit.
func runCmd(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = gitCleanEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
