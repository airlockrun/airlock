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
	// directory renames). Holding a Postgres transaction across multi-
	// second git invocations is a footgun; nothing in this migration
	// touches the DB anyway.
	goose.AddMigrationNoTxContext(upSplitMonorepo, downSplitMonorepo)
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
