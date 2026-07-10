// Package builder implements the agent build and upgrade pipeline.
package builder

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/airlockrun/agentsdk/scaffold"
)

const (
	gitUserEmail = "airlock@localhost"
	gitUserName  = "Airlock"
)

// Per-agent repo layout:
//
//	<basePath>/                     ← AgentReposPath
//	├── <agentID-1>/                ← per-agent repo working tree
//	│   ├── .git/
//	│   ├── main.go
//	│   ├── go.mod
//	│   ├── ...
//	├── <agentID-2>/
//	│   └── ...
//
// AgentRepoPath returns the working-tree path for a single agent's repo.
func AgentRepoPath(basePath, agentID string) string {
	return filepath.Join(basePath, agentID)
}

// InitAgentRepo initializes a per-agent git repo at <basePath>/<agentID>/
// if it doesn't already exist. Idempotent. The initial commit (with a
// bootstrap .gitignore) gives the repo a HEAD so subsequent
// `git checkout main` works without complaints; CommitScaffold overwrites
// that .gitignore with the canonical scaffold template moments later.
func InitAgentRepo(basePath, agentID string) error {
	path := AgentRepoPath(basePath, agentID)
	if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
		if err := EnsureGitIdentity(path); err != nil {
			return err
		}
		return nil // already initialized
	}

	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}

	if err := git(path, "init", "-b", "main"); err != nil {
		return fmt.Errorf("git init: %w", err)
	}

	if err := EnsureGitIdentity(path); err != nil {
		return err
	}

	// Bootstrap .gitignore just so the init commit has content; the
	// scaffold template replaces it (it carries the canonical entries —
	// go.work pair, build artifacts). Dockerfile is intentionally NOT
	// ignored (it is committed for local/remote builds), and DIAGNOSTICS.md
	// is kept out of commits by the codegen sync step, not by .gitignore.
	if err := os.WriteFile(filepath.Join(path, ".gitignore"), []byte("go.work\ngo.work.sum\n"), 0o644); err != nil {
		return fmt.Errorf("write .gitignore: %w", err)
	}
	if err := git(path, "add", ".gitignore"); err != nil {
		return fmt.Errorf("git add .gitignore: %w", err)
	}
	if err := git(path, "commit", "-m", "init"); err != nil {
		return fmt.Errorf("git initial commit: %w", err)
	}

	return nil
}

// CommitScaffold creates branch build/init in the agent's repo,
// materializes scaffold files at the repo root, and commits. Returns the
// commit hash. Safe to call on retry — deletes a stale branch first.
func CommitScaffold(repoPath string, data scaffold.ScaffoldData) (string, error) {
	const branch = "build/init"
	if err := EnsureGitIdentity(repoPath); err != nil {
		return "", err
	}

	// Clean up stale branch from a previous failed build attempt.
	// Must switch away from it first — can't delete the checked-out branch.
	_ = git(repoPath, "checkout", "main")
	_ = git(repoPath, "branch", "-D", branch)

	if err := git(repoPath, "checkout", "-b", branch); err != nil {
		return "", fmt.Errorf("git checkout -b %s: %w", branch, err)
	}

	// Materialize scaffold at the repo root (no agents/<id>/ nesting).
	if err := scaffold.Materialize(repoPath, data); err != nil {
		return "", fmt.Errorf("materialize scaffold: %w", err)
	}

	if err := git(repoPath, "add", "-A"); err != nil {
		return "", fmt.Errorf("git add: %w", err)
	}

	// Retry safety: a previous build may have already merged the same
	// scaffold to main. Since we just re-created the build branch from
	// main, the materialized files match what's already committed and
	// there's nothing to stage. Treat that as success — MergeBranch is a
	// no-op when the branch is already merged.
	status, err := gitOutput(repoPath, "status", "--porcelain")
	if err != nil {
		return "", fmt.Errorf("git status: %w", err)
	}
	if status == "" {
		hash, err := gitOutput(repoPath, "rev-parse", "HEAD")
		if err != nil {
			return "", fmt.Errorf("git rev-parse: %w", err)
		}
		return hash, nil
	}

	if err := git(repoPath, "commit", "-m", "scaffold"); err != nil {
		return "", fmt.Errorf("git commit: %w", err)
	}

	hash, err := gitOutput(repoPath, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git rev-parse: %w", err)
	}
	return hash, nil
}

// CreateBranch creates a new branch from main in repoPath.
func CreateBranch(repoPath, branch string) error {
	if err := git(repoPath, "checkout", "main"); err != nil {
		if err2 := git(repoPath, "checkout", "master"); err2 != nil {
			return fmt.Errorf("git checkout main: %w", err)
		}
	}
	_ = git(repoPath, "branch", "-D", branch)
	if err := git(repoPath, "checkout", "-b", branch); err != nil {
		return fmt.Errorf("git checkout -b %s: %w", branch, err)
	}
	return nil
}

// CreateUpgradeBranch creates branch upgrade/{runID} in the agent's repo
// off main. Uses `-B` (create-or-reset) so retries don't fail on a
// leftover branch from a prior failed attempt — Fix-this-error reuses
// the failed run's id as the branch suffix, and successful upgrades
// currently never delete the branch after merging, so collisions are
// easy to hit. Whatever was on the old branch was from a failed run and
// not worth keeping.
func CreateUpgradeBranch(repoPath, runID string) error {
	branch := upgradeBranchName(runID)

	if err := git(repoPath, "checkout", "main"); err != nil {
		if err2 := git(repoPath, "checkout", "master"); err2 != nil {
			return fmt.Errorf("git checkout main: %w", err)
		}
	}
	if err := git(repoPath, "checkout", "-B", branch); err != nil {
		return fmt.Errorf("git checkout -B %s: %w", branch, err)
	}
	return nil
}

// UpgradeBranchName returns the branch name an upgrade run lives on
// inside the agent's repo. Exposed so callers can hand the same name to
// MaterializeBranch and MergeBranch.
func UpgradeBranchName(runID string) string { return upgradeBranchName(runID) }

func upgradeBranchName(runID string) string { return "upgrade/" + runID }

// MaterializeBranch writes the tracked tree at branch into workDir with NO
// .git — `git archive <branch>` piped into `tar -x`. The codegen toolserver
// bind-mounts workDir at /workspace, so the LLM (which has bash + git + root
// in that container) sees plain source files and no git repository to push
// to or corrupt; airlock owns every git operation host-side in repoPath.
func MaterializeBranch(repoPath, branch, workDir string) error {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", workDir, err)
	}

	archive := exec.Command("git", "-C", repoPath, "archive", "--format=tar", branch)
	archive.Env = append(gitCleanEnv(), "GIT_TERMINAL_PROMPT=0")
	extract := exec.Command("tar", "-x", "-C", workDir)

	pipe, err := archive.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git archive stdout pipe: %w", err)
	}
	extract.Stdin = pipe

	var archiveErr, extractErr bytes.Buffer
	archive.Stderr = &archiveErr
	extract.Stderr = &extractErr

	if err := extract.Start(); err != nil {
		return fmt.Errorf("start tar: %w", err)
	}
	if err := archive.Run(); err != nil {
		_ = extract.Wait()
		return fmt.Errorf("git archive %s: %s", branch, strings.TrimSpace(archiveErr.String()))
	}
	if err := extract.Wait(); err != nil {
		return fmt.Errorf("tar extract: %s", strings.TrimSpace(extractErr.String()))
	}
	return nil
}

// SyncWorkdirToRepo mirrors workDir's file tree onto repoPath's working
// tree so a subsequent `git add -A` in repoPath records exactly the codegen
// agent's edits (adds, modifications, AND deletions). Paths in exclude are
// never copied into repoPath (and removed if already tracked) — used to keep
// the airlock-injected DIAGNOSTICS.md out of commits. repoPath's .git is
// never touched; workDir carries no .git (see MaterializeBranch).
func SyncWorkdirToRepo(workDir, repoPath string, exclude []string) error {
	ex := make(map[string]struct{}, len(exclude))
	for _, e := range exclude {
		ex[e] = struct{}{}
	}

	// 1. Copy every file from workDir into repoPath.
	err := filepath.WalkDir(workDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(workDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if skipWorkdirMirrorPath(rel, d.IsDir(), ex) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		dst := filepath.Join(repoPath, rel)
		if d.IsDir() {
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			return os.MkdirAll(dst, info.Mode().Perm())
		}
		return mirrorFile(path, dst)
	})
	if err != nil {
		return fmt.Errorf("mirror workdir: %w", err)
	}

	// 2. Delete tracked files the agent removed (in the index, absent from
	//    workDir) plus any excluded path that is tracked.
	tracked, err := gitOutput(repoPath, "ls-files")
	if err != nil {
		return fmt.Errorf("git ls-files: %w", err)
	}
	for _, rel := range strings.Split(tracked, "\n") {
		rel = strings.TrimSpace(rel)
		if rel == "" {
			continue
		}
		excluded := skipWorkdirMirrorPath(rel, false, ex)
		_, statErr := os.Stat(filepath.Join(workDir, rel))
		if excluded || errors.Is(statErr, fs.ErrNotExist) {
			if rmErr := os.Remove(filepath.Join(repoPath, rel)); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", rel, rmErr)
			}
		}
	}
	return nil
}

func skipWorkdirMirrorPath(rel string, isDir bool, exclude map[string]struct{}) bool {
	if _, skip := exclude[rel]; skip {
		return true
	}
	rel = filepath.ToSlash(rel)
	if _, skip := exclude[rel]; skip {
		return true
	}
	if rel == ".git" || strings.HasPrefix(rel, ".git/") {
		return true
	}
	if rel == ".airlock" || strings.HasPrefix(rel, ".airlock/") {
		return true
	}
	if isDir {
		switch rel {
		case "node_modules", ".cache", ".tmp":
			return true
		}
	}
	return false
}

// CommitWorktree stages and commits all changes in repoPath's working tree.
// Returns (HEAD, false, nil) without committing when the tree is clean, so
// callers can fall through to "current HEAD is the source ref". No push.
func CommitWorktree(repoPath, message string) (hash string, committed bool, err error) {
	if err := EnsureGitIdentity(repoPath); err != nil {
		return "", false, err
	}
	if err := git(repoPath, "add", "-A"); err != nil {
		return "", false, fmt.Errorf("git add: %w", err)
	}
	status, err := gitOutput(repoPath, "status", "--porcelain")
	if err != nil {
		return "", false, fmt.Errorf("git status: %w", err)
	}
	if status == "" {
		h, rerr := gitOutput(repoPath, "rev-parse", "HEAD")
		if rerr != nil {
			return "", false, fmt.Errorf("git rev-parse: %w", rerr)
		}
		return h, false, nil
	}
	if err := git(repoPath, "commit", "-m", message); err != nil {
		return "", false, fmt.Errorf("git commit: %w", err)
	}
	h, err := gitOutput(repoPath, "rev-parse", "HEAD")
	if err != nil {
		return "", false, fmt.Errorf("git rev-parse: %w", err)
	}
	return h, true, nil
}

// mirrorFile copies src to dst, creating parent dirs and preserving src's
// permission bits, truncating dst if it exists.
func mirrorFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// MergeBranch fast-forward merges branch into main, rebasing the branch
// onto current main first if a parallel commit advanced main while this
// branch's work was running. With per-agent repos each agent's history
// is isolated, so the rebase trivially fast-forwards in the common case;
// the fallback path handles the rare case of a manual commit landing on
// main (e.g. an operator hot-fix) in parallel with a build.
func MergeBranch(repoPath, branch string) error {
	mainBranch := "main"
	if err := git(repoPath, "checkout", "main"); err != nil {
		if err2 := git(repoPath, "checkout", "master"); err2 != nil {
			return fmt.Errorf("git checkout main: %w", err)
		}
		mainBranch = "master"
	}

	if err := git(repoPath, "merge", "--ff-only", branch); err == nil {
		return nil
	}

	if err := git(repoPath, "rebase", mainBranch, branch); err != nil {
		_ = git(repoPath, "rebase", "--abort")
		_ = git(repoPath, "checkout", mainBranch)
		return fmt.Errorf("git rebase %s onto %s: %w", branch, mainBranch, err)
	}
	if err := git(repoPath, "checkout", mainBranch); err != nil {
		return fmt.Errorf("git checkout %s after rebase: %w", mainBranch, err)
	}
	if err := git(repoPath, "merge", "--ff-only", branch); err != nil {
		return fmt.Errorf("git merge --ff-only %s after rebase: %w", branch, err)
	}
	return nil
}

// SaveRef creates a branch ref pointing at the given commit. Fails loud
// if the ref already exists — callers pick unique names (typically
// pre-rollback/{timestamp}) so a collision implies a bug, not a
// retry-safe noop.
func SaveRef(repoPath, refName, commit string) error {
	return git(repoPath, "branch", refName, commit)
}

// ResetHard moves the current branch HEAD to commit and forces the
// working tree to match. Caller is responsible for saving any forward
// commits with SaveRef first — they'll be unreachable from any branch
// after this returns (recoverable via reflog for the default 90-day
// window). Checks out main first so reset hits the right ref.
func ResetHard(repoPath, commit string) error {
	if err := git(repoPath, "checkout", "main"); err != nil {
		if err2 := git(repoPath, "checkout", "master"); err2 != nil {
			return fmt.Errorf("git checkout main: %w", err)
		}
	}
	if err := git(repoPath, "reset", "--hard", commit); err != nil {
		return fmt.Errorf("git reset --hard %s: %w", commit, err)
	}
	return nil
}

// CleanWorktree removes untracked files and directories from the working
// tree. It respects .gitignore (no -x), so airlock-generated ignored files
// (DIAGNOSTICS.md, Dockerfile) and regenerated build artefacts (*_templ.go,
// views/static) are left alone — only stray tracked-then-orphaned sources are
// removed. Used on a fresh build so files left behind by a prior failed
// build/codegen don't leak into the docker build context, which is the repo
// working tree itself.
func CleanWorktree(repoPath string) error {
	if err := git(repoPath, "clean", "-fd"); err != nil {
		return fmt.Errorf("git clean -fd: %w", err)
	}
	return nil
}

// MigrationVersionAt returns the highest goose version number among
// files in migrations/ at the given commit. Goose's contract is "all
// migrations get applied to head", so this is the version a deployed
// container ends up at — the answer rollback needs to give goose as
// its down-to target. Returns 0 when migrations/ is empty or absent.
//
// Parses the leading NNNN_ prefix from each filename (goose's required
// naming convention). Non-numeric files (README, etc.) are skipped.
func MigrationVersionAt(repoPath, commit string) (int, error) {
	out, err := gitOutput(repoPath, "ls-tree", "-r", "--name-only", commit, "--", "migrations/")
	if err != nil {
		return 0, fmt.Errorf("git ls-tree migrations/ at %s: %w", commit, err)
	}
	max := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		base := filepath.Base(line)
		us := strings.IndexByte(base, '_')
		if us <= 0 {
			continue
		}
		n := 0
		for _, c := range base[:us] {
			if c < '0' || c > '9' {
				n = -1
				break
			}
			n = n*10 + int(c-'0')
		}
		if n > max {
			max = n
		}
	}
	return max, nil
}

// CopyAgentRepo clones the srcID agent's repo into the dstID path as an
// independent repo — committed code + history, working tree checked out, no
// upstream remote (the clone is a new agent, not a fork tracking the source's
// on-disk path). --no-hardlinks so the two repos never share object storage.
// Used by agent clone; the destination must not already exist.
func CopyAgentRepo(basePath, srcID, dstID string) error {
	src := AgentRepoPath(basePath, srcID)
	dst := AgentRepoPath(basePath, dstID)
	if _, err := os.Stat(filepath.Join(src, ".git")); err != nil {
		return fmt.Errorf("source agent repo %s not initialized: %w", srcID, err)
	}
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("destination agent repo %s already exists", dstID)
	}
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", basePath, err)
	}
	if err := git(basePath, "clone", "--no-hardlinks", src, dst); err != nil {
		return fmt.Errorf("git clone %s: %w", srcID, err)
	}
	// Detach from the source path so the clone is standalone.
	_ = git(dst, "remote", "remove", "origin")
	if err := EnsureGitIdentity(dst); err != nil {
		return err
	}
	return nil
}

// EnsureGitIdentity sets the local git committer identity Airlock uses for
// repos it owns. It is safe to call repeatedly and never depends on global git
// config, which is not present in production containers.
func EnsureGitIdentity(repoPath string) error {
	if err := git(repoPath, "config", "--local", "user.email", gitUserEmail); err != nil {
		return fmt.Errorf("git config email: %w", err)
	}
	if err := git(repoPath, "config", "--local", "user.name", gitUserName); err != nil {
		return fmt.Errorf("git config name: %w", err)
	}
	return nil
}

// RemoveAgentRepo deletes the per-agent repo directory entirely.
// Idempotent — missing dir is not an error.
func RemoveAgentRepo(basePath, agentID string) error {
	path := AgentRepoPath(basePath, agentID)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove agent repo %s: %w", path, err)
	}
	return nil
}

// RecoverAgentRepo resets an agent repo to a clean default branch before a
// build, undoing whatever state a previous (possibly failed) build left
// behind: an in-progress merge/rebase, a stale `upgrade/*` branch left
// checked out, and uncommitted working-tree edits (airlock's own scratch —
// regenerated Dockerfile, a go.mod bump that never got committed, etc.).
//
// Without this, housekeeping (which runs before codegen's own checkout-main)
// operates on whatever branch was left checked out and commits there, so its
// go.mod bump never lands on main and the codegen clone takes main's stale
// committed go.mod.
//
// `git checkout -f main` switches to main AND discards working-tree changes
// in one shot. The failed `upgrade/*` branches are NOT deleted — they're
// kept for manual recovery; we just stop being checked out on one. The
// working-tree edits we discard are never user work: user changes reach the
// repo as commits (the external remote → PullAgentRepo → main). Codegen
// mirrors its edits into this working tree and commits them in-place
// (SyncWorkdirToRepo + CommitWorktree); a build that crashed between the
// mirror and the commit leaves uncommitted edits here, which is exactly the
// scratch this discards.
//
// No-op on a fresh path with no .git/ (initial build hasn't run `git init`
// yet). Returns true iff anything actually needed cleaning up, so the caller
// can log it — silent recovery hides the underlying crash/abandon pattern.
func RecoverAgentRepo(repoPath string) (recovered bool, err error) {
	if _, statErr := os.Stat(filepath.Join(repoPath, ".git")); statErr != nil {
		return false, nil
	}
	for _, op := range []string{"merge", "rebase", "cherry-pick"} {
		// git reports "no <op> in progress" with a non-zero exit; the
		// failure is the no-op case, not a real error.
		if err := runGit(repoPath, op, "--abort"); err == nil {
			recovered = true
		}
	}

	// Determine whether we're already on a clean default branch; if not,
	// a force-checkout is the recovery and we flag it.
	branch, _ := gitOutput(repoPath, "branch", "--show-current")
	status, _ := gitOutput(repoPath, "status", "--porcelain")
	onDefault := branch == "main" || branch == "master"
	if !onDefault || strings.TrimSpace(status) != "" {
		recovered = true
	}

	if err := runGit(repoPath, "checkout", "-f", "main"); err != nil {
		if err2 := runGit(repoPath, "checkout", "-f", "master"); err2 != nil {
			return recovered, fmt.Errorf("checkout -f main: %w", err)
		}
	}
	return recovered, nil
}

// git runs a git command in the given directory.
func git(dir string, args ...string) error {
	return runGit(dir, args...)
}

// runGit runs a git command in the given directory.
func runGit(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(gitCleanEnv(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// gitOutput runs a git command and returns its stdout.
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(gitCleanEnv(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// gitCleanEnv returns os.Environ() with git-context vars stripped. These
// leak in when builder tests run inside a pre-commit hook (git sets
// GIT_INDEX_FILE and friends pointing at the parent repo's in-flight
// index, which breaks any git subprocess that tries to use its own repo).
func gitCleanEnv() []string {
	env := os.Environ()
	out := env[:0]
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			out = append(out, kv)
			continue
		}
		k := kv[:eq]
		if strings.HasPrefix(k, "GIT_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
