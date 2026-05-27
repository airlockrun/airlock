package builder

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatAuthExtraHeader(t *testing.T) {
	a := &patAuth{token: "ghp_secret"}
	header, err := a.ExtraHeader(context.Background())
	if err != nil {
		t.Fatalf("ExtraHeader: %v", err)
	}
	const prefix = "Authorization: Basic "
	if !strings.HasPrefix(header, prefix) {
		t.Fatalf("header = %q, want prefix %q", header, prefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := "x-access-token:ghp_secret"
	if string(decoded) != want {
		t.Errorf("decoded = %q, want %q", decoded, want)
	}
}

func TestIsNonFastForward(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"non-fast-forward verbatim", errors.New("exit 1: ! [rejected] main -> main (non-fast-forward)"), true},
		{"updates were rejected", errors.New("exit 1: Updates were rejected because the tip of your current branch is behind"), true},
		{"hint fetch first", errors.New("exit 1: hint: ('git pull ...') before pushing again. hint: See the 'Note about fast-forwards' in 'git push --help' for details. fetch first"), true},
		{"network failure (not nff)", errors.New("exit 128: fatal: unable to access 'https://...': Could not resolve host"), false},
		{"auth failure (not nff)", errors.New("exit 128: fatal: Authentication failed"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNonFastForward(tt.err); got != tt.want {
				t.Errorf("isNonFastForward(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestPushConflictError(t *testing.T) {
	e := &PushConflictError{PreservedBranch: "airlock/upgrade/run-123", RemoteBranch: "main"}
	msg := e.Error()
	for _, want := range []string{"main", "airlock/upgrade/run-123", "preserved"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, missing %q", msg, want)
		}
	}
	// Also: errors.As recovers the typed error.
	var pce *PushConflictError
	if !errors.As(e, &pce) {
		t.Error("errors.As failed to extract *PushConflictError")
	}
}

// --- integration tests for pushBranch against a local bare "remote" ---

// makeBareRemote initializes a bare git repo at t.TempDir() and returns
// its path so a local clone can use it as a file:// remote.
func makeBareRemote(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := runGit(dir, "init", "--bare", "-b", "main"); err != nil {
		t.Fatalf("init bare: %v", err)
	}
	return dir
}

// cloneRemote clones the bare remote into a fresh temp dir and configures
// identity so the test can `git commit`. No content written — the caller
// is responsible for seeding if the remote was empty.
func cloneRemote(t *testing.T, remote string) string {
	t.Helper()
	dir := t.TempDir()
	if err := runGit(dir, "clone", remote, "."); err != nil {
		t.Fatalf("clone: %v", err)
	}
	if err := runGit(dir, "config", "user.email", "test@airlock"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(dir, "config", "user.name", "Test"); err != nil {
		t.Fatal(err)
	}
	return dir
}

// seedRemote clones an empty bare remote, writes + commits one file so
// HEAD is non-empty, and pushes back. Returns the seed working clone so
// the caller can keep building on it. Idempotent only on an empty
// remote — use cloneRemote for subsequent clones once the remote has
// commits.
func seedRemote(t *testing.T, remote string) string {
	t.Helper()
	dir := cloneRemote(t, remote)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runGit(dir, "add", "README.md"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(dir, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(dir, "push", remote, "main:main"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPushBranch_HappyPath(t *testing.T) {
	ctx := context.Background()
	remote := makeBareRemote(t)
	repo := cloneRemote(t, remote)

	// Need a commit to push.
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runGit(repo, "add", "README.md"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(repo, "commit", "-m", "initial"); err != nil {
		t.Fatal(err)
	}

	if err := pushBranch(ctx, repo, remote, "main", "", "run-1"); err != nil {
		t.Fatalf("pushBranch: %v", err)
	}

	// Bare remote should now have a "main" ref pointing to our commit.
	headOut, err := gitOutput(remote, "rev-parse", "main")
	if err != nil {
		t.Fatalf("rev-parse main on remote: %v", err)
	}
	want, _ := gitOutput(repo, "rev-parse", "HEAD")
	if headOut != want {
		t.Errorf("remote main = %q, want %q", headOut, want)
	}
}

func TestPushBranch_RebaseRetrySucceeds(t *testing.T) {
	ctx := context.Background()
	remote := makeBareRemote(t)
	repo := seedRemote(t, remote)

	// A SECOND clone makes a commit and pushes — moves the remote tip
	// ahead of our `repo`.
	other := cloneRemote(t, remote)
	if err := os.WriteFile(filepath.Join(other, "their.txt"), []byte("theirs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runGit(other, "add", "their.txt"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(other, "commit", "-m", "theirs"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(other, "push", remote, "main:main"); err != nil {
		t.Fatal(err)
	}

	// Now `repo` has a NON-conflicting local commit on top of the OLD
	// remote tip. pushBranch should fast-forward-fail, fetch, rebase
	// cleanly (different file), retry, succeed.
	if err := os.WriteFile(filepath.Join(repo, "ours.txt"), []byte("ours\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runGit(repo, "add", "ours.txt"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(repo, "commit", "-m", "ours"); err != nil {
		t.Fatal(err)
	}

	if err := pushBranch(ctx, repo, remote, "main", "", "run-rebase"); err != nil {
		t.Fatalf("pushBranch: %v", err)
	}

	// Remote main should now contain both their.txt and ours.txt.
	files, err := gitOutput(remote, "ls-tree", "-r", "--name-only", "main")
	if err != nil {
		t.Fatalf("ls-tree: %v", err)
	}
	for _, want := range []string{"their.txt", "ours.txt"} {
		if !strings.Contains(files, want) {
			t.Errorf("remote main missing %q after rebase-retry:\n%s", want, files)
		}
	}
}

func TestPushBranch_ConflictPreservesOnSideBranch(t *testing.T) {
	ctx := context.Background()
	remote := makeBareRemote(t)
	repo := seedRemote(t, remote)

	// Both `repo` and `other` edit the SAME file — guaranteed rebase
	// conflict when `repo` tries to push after `other` lands.
	other := cloneRemote(t, remote)
	if err := os.WriteFile(filepath.Join(other, "README.md"), []byte("theirs version\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runGit(other, "add", "README.md"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(other, "commit", "-m", "their edit"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(other, "push", remote, "main:main"); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("ours version\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runGit(repo, "add", "README.md"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(repo, "commit", "-m", "our edit"); err != nil {
		t.Fatal(err)
	}
	codegenSHA, _ := gitOutput(repo, "rev-parse", "HEAD")

	err := pushBranch(ctx, repo, remote, "main", "", "run-conflict")
	var pce *PushConflictError
	if !errors.As(err, &pce) {
		t.Fatalf("expected *PushConflictError, got %T: %v", err, err)
	}
	if pce.PreservedBranch != "airlock/upgrade/run-conflict" {
		t.Errorf("PreservedBranch = %q, want airlock/upgrade/run-conflict", pce.PreservedBranch)
	}
	if pce.RemoteBranch != "main" {
		t.Errorf("RemoteBranch = %q, want main", pce.RemoteBranch)
	}

	// Remote must carry the side branch with the codegen commit.
	sideSHA, err := gitOutput(remote, "rev-parse", "refs/heads/airlock/upgrade/run-conflict")
	if err != nil {
		t.Fatalf("remote missing side branch: %v", err)
	}
	if sideSHA != codegenSHA {
		t.Errorf("side branch SHA = %q, want codegen SHA %q", sideSHA, codegenSHA)
	}

	// Remote main must still point at THEIR commit (our push got rejected).
	remoteMain, _ := gitOutput(remote, "rev-parse", "main")
	if remoteMain == codegenSHA {
		t.Error("remote main moved to codegen SHA; should still point at their commit")
	}

	// Local repo must be reset to the remote main, clean working tree.
	localHEAD, _ := gitOutput(repo, "rev-parse", "HEAD")
	if localHEAD != remoteMain {
		t.Errorf("local HEAD = %q, want remote main %q", localHEAD, remoteMain)
	}
	status, _ := gitOutput(repo, "status", "--porcelain")
	if status != "" {
		t.Errorf("local working tree dirty after conflict reset:\n%s", status)
	}
}
