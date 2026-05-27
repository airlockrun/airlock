package builder

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

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
