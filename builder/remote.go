package builder

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// RemoteState summarizes a git remote as seen via ls-remote with a credential.
type RemoteState struct {
	Empty          bool   // the remote advertises no branches at all
	HasBranch      bool   // the requested branch exists on the remote
	HeadSHA        string // tip SHA of the requested branch ("" when absent)
	DefaultBranch  string // the remote's HEAD branch (from the symref), "" if none
	DefaultHeadSHA string // tip SHA of the default branch ("" when unknown)
}

// ImportBranch returns the branch to adopt when importing: the requested one
// when it exists on the remote, otherwise the remote's default branch. Empty
// only when the remote has no branch to import.
func (s RemoteState) ImportBranch(requested string) string {
	if s.HasBranch {
		return requested
	}
	return s.DefaultBranch
}

// InspectRemote validates that remote is reachable with credID and reports
// whether it has any branches (empty vs populated) and whether branch exists.
// Used at git-connect time to (1) fail fast on a bad/expired token or wrong URL
// instead of silently saving and breaking on the next build, and (2) drive the
// empty→mirror / non-empty→import decision. Runs ls-remote from a throwaway
// temp dir — it's a pure remote query and touches no agent repo.
func (b *BuildService) InspectRemote(ctx context.Context, remote, branch string, credID pgtype.UUID) (RemoteState, error) {
	q := dbq.New(b.db.Pool())
	auth, err := resolveGitAuth(ctx, q, b.encryptor, credID)
	if err != nil {
		return RemoteState{}, err
	}
	header, err := auth.ExtraHeader(ctx)
	if err != nil {
		return RemoteState{}, err
	}
	dir, err := os.MkdirTemp("", "airlock-lsremote-")
	if err != nil {
		return RemoteState{}, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	out, err := gitAuthedOutput(ctx, dir, header, "ls-remote", "--symref", remote)
	if err != nil {
		// Redact the auth header defensively before the error escapes to logs.
		return RemoteState{}, fmt.Errorf("%s", strings.ReplaceAll(err.Error(), header, "[redacted]"))
	}

	return parseRemoteState(out, branch), nil
}

// ValidateRemoteWrite verifies that credID can push the selected branch without
// changing the remote. It clones populated remotes and creates an ephemeral
// commit for empty remotes, then uses git push --dry-run.
func (b *BuildService) ValidateRemoteWrite(ctx context.Context, remote, branch string, credID pgtype.UUID, empty bool) error {
	q := dbq.New(b.db.Pool())
	auth, err := resolveGitAuth(ctx, q, b.encryptor, credID)
	if err != nil {
		return err
	}
	header, err := auth.ExtraHeader(ctx)
	if err != nil {
		return err
	}
	if branch == "" {
		branch = "main"
	}
	root, err := os.MkdirTemp("", "airlock-git-write-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	repo := filepath.Join(root, "repo")
	if empty {
		if err := os.Mkdir(repo, 0o755); err != nil {
			return err
		}
		if err := git(repo, "init", "--initial-branch", branch); err != nil {
			return err
		}
		if err := EnsureGitIdentity(repo); err != nil {
			return err
		}
		if err := git(repo, "commit", "--allow-empty", "-m", "Airlock write permission probe"); err != nil {
			return err
		}
	} else if err := gitAuthed(ctx, root, header, "clone", "--depth", "1", "--branch", branch, "--single-branch", remote, repo); err != nil {
		return fmt.Errorf("clone for write check: %w", err)
	}
	if err := gitAuthed(ctx, repo, header, "push", "--dry-run", remote, "HEAD:refs/heads/"+branch); err != nil {
		return fmt.Errorf("credential cannot push branch %s: %w", branch, err)
	}
	return nil
}

// CloneRemoteIntoAgent clones remote's branch into the agent's repo path so a
// not-yet-built agent can adopt an existing external codebase (import). It
// replaces any existing repo dir and verifies the result is a Go project. The
// caller triggers a SkipScaffold build afterwards to compile the imported HEAD —
// re-scaffolding would clobber the imported files, exactly as for a clone.
func (b *BuildService) CloneRemoteIntoAgent(ctx context.Context, agentID, remote, branch string, credID pgtype.UUID) error {
	lock, err := b.AcquireSourceLock(ctx, agentID)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	q := dbq.New(b.db.Pool())
	auth, err := resolveGitAuth(ctx, q, b.encryptor, credID)
	if err != nil {
		return err
	}
	header, err := auth.ExtraHeader(ctx)
	if err != nil {
		return err
	}
	if branch == "" {
		branch = "main"
	}
	if err := os.MkdirAll(b.ReposPath(), 0o755); err != nil {
		return fmt.Errorf("ensure repos dir: %w", err)
	}
	repoPath := b.AgentRepoPath(agentID)
	if err := os.RemoveAll(repoPath); err != nil {
		return fmt.Errorf("clear repo path: %w", err)
	}
	if err := gitAuthed(ctx, b.ReposPath(), header, "clone", "--branch", branch, "--single-branch", remote, repoPath); err != nil {
		_ = os.RemoveAll(repoPath)
		return fmt.Errorf("clone: %s", strings.ReplaceAll(err.Error(), header, "[redacted]"))
	}
	if err := EnsureGitIdentity(repoPath); err != nil {
		_ = os.RemoveAll(repoPath)
		return err
	}
	if _, err := os.Stat(filepath.Join(repoPath, "go.mod")); err != nil {
		_ = os.RemoveAll(repoPath)
		return fmt.Errorf("imported repository has no go.mod at its root — not a valid agent project")
	}
	return nil
}

// RemoteSharesHistory fetches the remote branch into the agent's repo and
// reports whether it shares any history with the agent's local HEAD (a common
// ancestor exists). Used at connect time to tell a same-repo reconnect (safe —
// the normal push/pull reconciles with no data loss) from a different, unrelated
// repo (dangerous — on a push conflict the agent resets its main to the remote's
// unrelated code). The fetch only updates FETCH_HEAD; it never moves a branch.
func (b *BuildService) RemoteSharesHistory(ctx context.Context, agentID, remote, branch string, credID pgtype.UUID) (bool, error) {
	q := dbq.New(b.db.Pool())
	auth, err := resolveGitAuth(ctx, q, b.encryptor, credID)
	if err != nil {
		return false, err
	}
	header, err := auth.ExtraHeader(ctx)
	if err != nil {
		return false, err
	}
	if branch == "" {
		branch = "main"
	}
	repoPath := b.AgentRepoPath(agentID)
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err != nil {
		return false, fmt.Errorf("agent has no local repository to compare against")
	}
	if err := gitAuthed(ctx, repoPath, header, "fetch", "--no-tags", remote, branch); err != nil {
		return false, fmt.Errorf("fetch remote: %s", strings.ReplaceAll(err.Error(), header, "[redacted]"))
	}
	return hasCommonAncestor(ctx, repoPath, "HEAD", "FETCH_HEAD")
}

// hasCommonAncestor reports whether two revs share history. git merge-base exits
// 0 when a common ancestor exists, 1 when the histories are unrelated; any other
// exit code is a genuine error.
func hasCommonAncestor(ctx context.Context, dir, a, b string) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "merge-base", a, b)
	cmd.Dir = dir
	cmd.Env = append(gitCleanEnv(), "GIT_TERMINAL_PROMPT=0")
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("merge-base: %w", err)
	}
	return true, nil
}

// parseRemoteState interprets `git ls-remote --symref` output: the symref line
// ("ref: refs/heads/<default>\tHEAD") gives the default branch, and each
// "<sha>\trefs/heads/<name>" line a branch. Empty when no branch is advertised.
// Only refs/heads/* count — HEAD and tags are ignored.
func parseRemoteState(lsRemoteOutput, branch string) RemoteState {
	if branch == "" {
		branch = "main"
	}
	st := RemoteState{Empty: true}
	for _, line := range strings.Split(lsRemoteOutput, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Symbolic-ref line for the default branch: "ref: refs/heads/main\tHEAD".
		if strings.HasPrefix(line, "ref: ") {
			f := strings.Fields(strings.TrimPrefix(line, "ref: "))
			if len(f) >= 2 && f[1] == "HEAD" {
				st.DefaultBranch = strings.TrimPrefix(f[0], "refs/heads/")
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || !strings.HasPrefix(f[1], "refs/heads/") {
			continue // HEAD dereference line, tags, etc.
		}
		st.Empty = false
		name := strings.TrimPrefix(f[1], "refs/heads/")
		if name == branch {
			st.HasBranch = true
			st.HeadSHA = f[0]
		}
		if name == st.DefaultBranch {
			st.DefaultHeadSHA = f[0]
		}
	}
	return st
}

// randomHexBytes returns n random bytes hex-encoded. Used to mint
// per-agent webhook secrets.
func randomHexBytes(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// gitAuth knows how to inject credentials into a git command targeting
// an external remote without embedding the secret in the URL (which
// leaks into .git/config and error messages). One impl in v1: PAT via
// HTTP Basic. v2 (GitHub App) returns a short-lived installation token
// resolved on demand.
type gitAuth interface {
	// ExtraHeader returns the value for `git -c http.extraheader=...`.
	// Format: "Authorization: Basic <b64>" or "Authorization: Bearer …".
	ExtraHeader(ctx context.Context) (string, error)
}

type patAuth struct{ token string }

func (p *patAuth) ExtraHeader(ctx context.Context) (string, error) {
	// "x-access-token:<token>" Basic — universal PAT format that works
	// against GitHub, GitLab, Bitbucket. The username placeholder is
	// ignored by all three; only the token side matters.
	creds := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + p.token))
	return "Authorization: Basic " + creds, nil
}

// resolveGitAuth loads + decrypts the credential pointed at by credID
// and returns a gitAuth ready to inject into push/fetch.
func resolveGitAuth(ctx context.Context, q *dbq.Queries, enc secrets.Store, credID pgtype.UUID) (gitAuth, error) {
	if !credID.Valid {
		return nil, fmt.Errorf("git credential id is missing")
	}
	row, err := q.GetGitCredential(ctx, credID)
	if err != nil {
		return nil, fmt.Errorf("load git credential: %w", err)
	}
	switch row.Type {
	case "pat":
		token, err := enc.Get(ctx, "git_credential/"+uuidString(row.ID)+"/token", row.TokenRef)
		if err != nil {
			return nil, fmt.Errorf("decrypt git credential token: %w", err)
		}
		return &patAuth{token: token}, nil
	default:
		return nil, fmt.Errorf("unsupported git credential type %q (v1 supports pat only)", row.Type)
	}
}

// PushConflictError signals that the codegen commit conflicted with a
// concurrent user push on the same branch. The conflicting codegen work
// is preserved on PreservedBranch (e.g. "airlock/upgrade/{runID}")
// pushed to the remote (and also kept as a local ref). The local main
// is reset to the remote tip so subsequent builds start clean.
type PushConflictError struct {
	PreservedBranch string
	RemoteBranch    string
}

func (e *PushConflictError) Error() string {
	return fmt.Sprintf(
		"your push to %s landed first and conflicts with this upgrade. The codegen work is preserved at branch %s on your remote — open a PR to merge it, or re-run the upgrade with a fresh prompt.",
		e.RemoteBranch, e.PreservedBranch)
}

// pushAgentRepo pushes the agent repo's current default branch to the
// configured remote. On non-fast-forward it fetches the remote tip,
// rebases the local commits on top, and retries; an unresolvable
// rebase conflict is captured as a PushConflictError with the codegen
// work preserved on a side branch.
//
// No-op for agents without a remote configured.
func (b *BuildService) pushAgentRepo(ctx context.Context, agent dbq.Agent, runID string) error {
	if agent.GitRemoteUrl == "" {
		return nil
	}
	q := dbq.New(b.db.Pool())
	auth, err := resolveGitAuth(ctx, q, b.encryptor, agent.GitCredentialID)
	if err != nil {
		return err
	}
	header, err := auth.ExtraHeader(ctx)
	if err != nil {
		return err
	}

	repoPath := b.AgentRepoPath(uuidString(agent.ID))
	branch := agent.GitDefaultBranch
	if branch == "" {
		branch = "main"
	}

	if err := pushBranch(ctx, repoPath, agent.GitRemoteUrl, branch, header, runID); err != nil {
		return err
	}
	return touchGitCredentialUsage(ctx, q, agent.GitCredentialID)
}

// pushBranch runs the credentialed git-push pipeline against a remote:
// try a fast-forward push; on rejection, fetch + rebase + retry; on
// unresolvable rebase conflict, preserve the local commit on a side
// branch (push to a new ref always fast-forwards, fall back to a local
// branch if the remote push also fails) and reset main to the remote
// tip, returning *PushConflictError.
//
// Split out from pushAgentRepo so the credential-free pipeline can be
// exercised against a local bare repo in tests without a DB or encryptor.
// header may be empty — gitAuthed will then omit the http.extraheader
// flag, which is fine for unauthenticated remotes (file://, ssh).
func pushBranch(ctx context.Context, repoPath, remote, branch, header, runID string) error {
	if err := gitAuthed(ctx, repoPath, header, "push", remote, branch+":"+branch); err == nil {
		return nil
	} else if !isNonFastForward(err) {
		return fmt.Errorf("git push: %w", err)
	}
	if err := gitAuthed(ctx, repoPath, header, "fetch", remote, branch); err != nil {
		return fmt.Errorf("git fetch for rebase: %w", err)
	}
	// Safety net: never replay our commits onto a remote we don't share history
	// with. That's how a fresh/scaffold agent pointed at a populated repo would
	// overwrite it — refuse loudly instead of rebasing over someone else's code.
	// The create/connect flows already route a populated remote to import; this
	// guards the push layer so any future misdetection can't clobber a repo.
	shared, sErr := hasCommonAncestor(ctx, repoPath, "HEAD", "FETCH_HEAD")
	if sErr != nil {
		return fmt.Errorf("verify shared history with %s: %w", remote, sErr)
	}
	if !shared {
		return fmt.Errorf("refusing to push to %s: its history is unrelated to this agent's code — pushing would overwrite the existing repository. Attach an empty repo, or import this one (Source tab, or create-from-repo)", remote)
	}
	if rebaseErr := git(repoPath, "rebase", "FETCH_HEAD"); rebaseErr != nil {
		_ = git(repoPath, "rebase", "--abort")
		preserveBranch := "airlock/upgrade/" + runID
		if err := gitAuthed(ctx, repoPath, header, "push", remote, "HEAD:refs/heads/"+preserveBranch); err != nil {
			_ = git(repoPath, "branch", preserveBranch)
		}
		_ = git(repoPath, "reset", "--hard", "FETCH_HEAD")
		return &PushConflictError{PreservedBranch: preserveBranch, RemoteBranch: branch}
	}
	if err := gitAuthed(ctx, repoPath, header, "push", remote, branch+":"+branch); err != nil {
		return fmt.Errorf("git push after rebase: %w", err)
	}
	return nil
}

// PullAgentRepo fetches the configured remote branch and fast-forwards
// the local main to it. Used by the webhook receiver: when a user push
// is announced, airlock pulls before enqueueing a rebuild so Execute
// sees the new HEAD. Errors if the local working tree has uncommitted
// changes (shouldn't happen in steady state).
func (b *BuildService) PullAgentRepo(ctx context.Context, agent dbq.Agent) (string, error) {
	if agent.GitRemoteUrl == "" {
		return "", fmt.Errorf("agent has no git remote configured")
	}
	lock, err := b.AcquireSourceLock(ctx, uuidString(agent.ID))
	if err != nil {
		return "", err
	}
	defer lock.Unlock()
	q := dbq.New(b.db.Pool())
	auth, err := resolveGitAuth(ctx, q, b.encryptor, agent.GitCredentialID)
	if err != nil {
		return "", err
	}
	header, err := auth.ExtraHeader(ctx)
	if err != nil {
		return "", err
	}

	repoPath := b.AgentRepoPath(uuidString(agent.ID))
	branch := agent.GitDefaultBranch
	if branch == "" {
		branch = "main"
	}

	if err := gitAuthed(ctx, repoPath, header, "fetch", agent.GitRemoteUrl, branch); err != nil {
		return "", fmt.Errorf("git fetch: %w", err)
	}
	if err := git(repoPath, "reset", "--hard", "FETCH_HEAD"); err != nil {
		return "", fmt.Errorf("git reset --hard FETCH_HEAD: %w", err)
	}
	hash, err := gitOutput(repoPath, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("rev-parse HEAD: %w", err)
	}
	if err := touchGitCredentialUsage(ctx, q, agent.GitCredentialID); err != nil {
		// Best-effort — don't fail the pull on a usage-stamp error.
		b.logger.Warn("touch git credential usage", zap.Error(err))
	}
	return hash, nil
}

// gitAuthed runs a git command with -c http.extraheader=<header> so
// the credential is passed via the Authorization HTTP header instead of
// being embedded in the URL (where it would land in .git/config).
func gitAuthed(_ context.Context, dir, header string, args ...string) error {
	full := args
	// Skip the -c flag entirely when no header is supplied — covers
	// unauthenticated transports (file://, ssh-with-agent) and keeps
	// tests against local bare repos from setting an empty config that
	// older git releases reject.
	if header != "" {
		full = append([]string{"-c", "http.extraheader=" + header}, args...)
	}
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(gitCleanEnv(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		// Strip any echoed header content from error output as a belt-
		// and-suspenders against accidental token leakage in logs.
		// Skip when header is empty — strings.ReplaceAll with old=""
		// splices the replacement between every character.
		if header != "" {
			msg = strings.ReplaceAll(msg, header, "[redacted]")
		}
		return fmt.Errorf("%s: %s", err, msg)
	}
	return nil
}

// isNonFastForward inspects a git push error to determine if the
// failure was specifically a non-fast-forward (the only failure we
// retry via rebase). Matches the canonical strings git uses across
// the major providers.
func isNonFastForward(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "non-fast-forward") ||
		strings.Contains(s, "Updates were rejected") ||
		strings.Contains(s, "fetch first")
}

func touchGitCredentialUsage(ctx context.Context, q *dbq.Queries, credID pgtype.UUID) error {
	if !credID.Valid {
		return nil
	}
	return q.TouchGitCredentialUsage(ctx, credID)
}
