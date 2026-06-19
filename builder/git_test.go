package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/scaffold"
)

func TestInitAgentRepo(t *testing.T) {
	base := t.TempDir()
	agentID := "agent-x"

	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}

	repoPath := AgentRepoPath(base, agentID)
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err != nil {
		t.Fatal(".git directory not found")
	}

	// Verify HEAD is main (or master) so subsequent checkouts find it.
	branch, err := gitOutput(repoPath, "branch", "--show-current")
	if err != nil {
		t.Fatalf("get branch: %v", err)
	}
	if branch != "main" && branch != "master" {
		t.Fatalf("expected main or master, got %q", branch)
	}

	log, err := gitOutput(repoPath, "log", "--oneline")
	if err != nil {
		t.Fatalf("git log: %v", err)
	}
	if !strings.Contains(log, "init") {
		t.Fatalf("expected init commit, got %q", log)
	}

	// Idempotent — second call must not error or wipe state.
	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo (idempotent): %v", err)
	}
}

func TestCommitScaffold(t *testing.T) {
	base := t.TempDir()
	agentID := "scaffold-agent"
	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	repoPath := AgentRepoPath(base, agentID)

	data := scaffold.ScaffoldData{
		AgentID:         agentID,
		Module:          "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v1.0.0",
	}
	hash, err := CommitScaffold(repoPath, data)
	if err != nil {
		t.Fatalf("CommitScaffold: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty commit hash")
	}

	branches, err := gitOutput(repoPath, "branch")
	if err != nil {
		t.Fatalf("git branch: %v", err)
	}
	if !strings.Contains(branches, "build/init") {
		t.Fatalf("branch build/init not found in: %s", branches)
	}

	// Per-agent layout: files at the repo root, no agents/<id>/ nesting.
	if _, err := os.Stat(filepath.Join(repoPath, "main.go")); err != nil {
		t.Fatal("main.go not found at repo root after scaffold")
	}
}

// scaffoldedRepo inits a per-agent repo, commits the scaffold, and merges to
// main — the steady state the codegen git helpers operate on.
func scaffoldedRepo(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	agentID := "git-helper-agent"
	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	repoPath := AgentRepoPath(base, agentID)
	data := scaffold.ScaffoldData{
		AgentID:         agentID,
		Module:          "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v1.0.0",
	}
	if _, err := CommitScaffold(repoPath, data); err != nil {
		t.Fatalf("CommitScaffold: %v", err)
	}
	if err := MergeBranch(repoPath, "build/init"); err != nil {
		t.Fatalf("MergeBranch: %v", err)
	}
	return repoPath
}

func TestMaterializeBranch(t *testing.T) {
	repoPath := scaffoldedRepo(t)
	workDir := filepath.Join(t.TempDir(), "ws")

	if err := MaterializeBranch(repoPath, "main", workDir); err != nil {
		t.Fatalf("MaterializeBranch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "main.go")); err != nil {
		t.Fatal("main.go not materialized at workdir root")
	}
	// The whole point: no .git reachable by the codegen container.
	if _, err := os.Stat(filepath.Join(workDir, ".git")); !os.IsNotExist(err) {
		t.Fatalf("workDir must not contain .git, got stat err=%v", err)
	}
}

func TestSyncWorkdirToRepoAndCommit(t *testing.T) {
	repoPath := scaffoldedRepo(t)
	workDir := filepath.Join(t.TempDir(), "ws")
	if err := MaterializeBranch(repoPath, "main", workDir); err != nil {
		t.Fatalf("MaterializeBranch: %v", err)
	}

	// Agent edits: modify a tracked file, add a new one, delete a tracked
	// one, and drop an excluded DIAGNOSTICS.md that must never be committed.
	if err := os.WriteFile(filepath.Join(workDir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("modify main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "added.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("add file: %v", err)
	}
	if err := os.Remove(filepath.Join(workDir, "go.mod")); err != nil {
		t.Fatalf("delete go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "DIAGNOSTICS.md"), []byte("secret context"), 0o644); err != nil {
		t.Fatalf("write DIAGNOSTICS.md: %v", err)
	}

	if err := SyncWorkdirToRepo(workDir, repoPath, []string{"DIAGNOSTICS.md"}); err != nil {
		t.Fatalf("SyncWorkdirToRepo: %v", err)
	}

	// repoPath working tree should mirror workDir minus DIAGNOSTICS.md.
	if _, err := os.Stat(filepath.Join(repoPath, "added.go")); err != nil {
		t.Error("added.go not mirrored into repo")
	}
	if _, err := os.Stat(filepath.Join(repoPath, "go.mod")); !os.IsNotExist(err) {
		t.Errorf("go.mod should have been deleted from repo, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(repoPath, "DIAGNOSTICS.md")); !os.IsNotExist(err) {
		t.Error("DIAGNOSTICS.md must not be mirrored into repo")
	}

	hash, committed, err := CommitWorktree(repoPath, "test change")
	if err != nil {
		t.Fatalf("CommitWorktree: %v", err)
	}
	if !committed || hash == "" {
		t.Fatalf("expected a commit, got committed=%v hash=%q", committed, hash)
	}

	// DIAGNOSTICS.md must not be tracked in the resulting commit.
	tracked, err := gitOutput(repoPath, "ls-files")
	if err != nil {
		t.Fatalf("ls-files: %v", err)
	}
	if strings.Contains(tracked, "DIAGNOSTICS.md") {
		t.Error("DIAGNOSTICS.md leaked into the commit")
	}
	if !strings.Contains(tracked, "added.go") {
		t.Error("added.go not tracked after commit")
	}
	if strings.Contains(tracked, "go.mod") {
		t.Error("go.mod deletion not committed")
	}
}

func TestCommitWorktreeCleanTreeNoOp(t *testing.T) {
	repoPath := scaffoldedRepo(t)
	hash, committed, err := CommitWorktree(repoPath, "no changes")
	if err != nil {
		t.Fatalf("CommitWorktree: %v", err)
	}
	if committed {
		t.Error("clean tree should not produce a commit")
	}
	if hash == "" {
		t.Error("clean-tree no-op should still return current HEAD")
	}
}

func TestMergeBranch(t *testing.T) {
	base := t.TempDir()
	agentID := "merge-agent"
	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	repoPath := AgentRepoPath(base, agentID)

	data := scaffold.ScaffoldData{
		AgentID:         agentID,
		Module:          "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v1.0.0",
	}
	if _, err := CommitScaffold(repoPath, data); err != nil {
		t.Fatalf("CommitScaffold: %v", err)
	}
	if err := MergeBranch(repoPath, "build/init"); err != nil {
		t.Fatalf("MergeBranch: %v", err)
	}

	curr, err := gitOutput(repoPath, "branch", "--show-current")
	if err != nil {
		t.Fatalf("get branch: %v", err)
	}
	if curr != "main" && curr != "master" {
		t.Fatalf("expected main or master after merge, got %q", curr)
	}
	if _, err := os.Stat(filepath.Join(repoPath, "main.go")); err != nil {
		t.Fatal("main.go not found at repo root after merge")
	}
}

func TestSaveRefAndResetHard(t *testing.T) {
	base := t.TempDir()
	agentID := "ref-agent"
	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	repoPath := AgentRepoPath(base, agentID)

	data := scaffold.ScaffoldData{
		AgentID:         agentID,
		Module:          "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v1.0.0",
	}
	firstHash, err := CommitScaffold(repoPath, data)
	if err != nil {
		t.Fatalf("CommitScaffold: %v", err)
	}
	if err := MergeBranch(repoPath, "build/init"); err != nil {
		t.Fatalf("MergeBranch: %v", err)
	}

	// Add a second commit on main to roll back from.
	if err := os.WriteFile(filepath.Join(repoPath, "feature.txt"), []byte("forward work"), 0o644); err != nil {
		t.Fatalf("write feature: %v", err)
	}
	if err := git(repoPath, "add", "feature.txt"); err != nil {
		t.Fatalf("git add: %v", err)
	}
	if err := git(repoPath, "commit", "-m", "feature"); err != nil {
		t.Fatalf("git commit: %v", err)
	}
	secondHash, err := gitOutput(repoPath, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}

	// Save current HEAD as a recovery ref, then reset main to the first
	// commit. Verify both are reachable from the right places.
	if err := SaveRef(repoPath, "pre-rollback/test", "HEAD"); err != nil {
		t.Fatalf("SaveRef: %v", err)
	}
	// Saving the same ref again must fail — caller must pick a unique name.
	if err := SaveRef(repoPath, "pre-rollback/test", "HEAD"); err == nil {
		t.Fatal("SaveRef should fail on existing ref")
	}

	if err := ResetHard(repoPath, firstHash); err != nil {
		t.Fatalf("ResetHard: %v", err)
	}
	head, err := gitOutput(repoPath, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("rev-parse HEAD: %v", err)
	}
	if head != firstHash {
		t.Fatalf("HEAD = %s, want %s after reset", head, firstHash)
	}

	// The forward commit must still be reachable via the saved ref.
	savedHead, err := gitOutput(repoPath, "rev-parse", "pre-rollback/test")
	if err != nil {
		t.Fatalf("rev-parse saved ref: %v", err)
	}
	if savedHead != secondHash {
		t.Fatalf("pre-rollback/test = %s, want %s", savedHead, secondHash)
	}

	// Working tree should be back to the first commit's state.
	if _, err := os.Stat(filepath.Join(repoPath, "feature.txt")); !os.IsNotExist(err) {
		t.Fatalf("feature.txt should be gone after reset, stat: %v", err)
	}
}

func TestMigrationVersionAt(t *testing.T) {
	base := t.TempDir()
	agentID := "mig-agent"
	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	repoPath := AgentRepoPath(base, agentID)

	// Commit A: no migrations dir at all.
	commitA, err := gitOutput(repoPath, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	if v, err := MigrationVersionAt(repoPath, commitA); err != nil || v != 0 {
		t.Fatalf("commit A: got v=%d err=%v, want 0,nil", v, err)
	}

	// Commit B: add 0001 + 0003 migrations and a README (skip non-numeric).
	mig := filepath.Join(repoPath, "migrations")
	if err := os.MkdirAll(mig, 0o755); err != nil {
		t.Fatalf("mkdir migrations: %v", err)
	}
	for _, name := range []string{"0001_init.sql", "0003_users.go", "README.md"} {
		if err := os.WriteFile(filepath.Join(mig, name), []byte("-- "+name), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := git(repoPath, "add", "migrations"); err != nil {
		t.Fatalf("git add migrations: %v", err)
	}
	if err := git(repoPath, "commit", "-m", "add migrations"); err != nil {
		t.Fatalf("git commit: %v", err)
	}
	commitB, err := gitOutput(repoPath, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	if v, err := MigrationVersionAt(repoPath, commitB); err != nil || v != 3 {
		t.Fatalf("commit B: got v=%d err=%v, want 3,nil", v, err)
	}

	// Commit A still resolves to 0 even though commit B has migrations.
	if v, err := MigrationVersionAt(repoPath, commitA); err != nil || v != 0 {
		t.Fatalf("commit A re-check: got v=%d err=%v, want 0,nil", v, err)
	}
}

func TestRemoveAgentRepo(t *testing.T) {
	base := t.TempDir()
	agentID := "rm-agent"
	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	if err := RemoveAgentRepo(base, agentID); err != nil {
		t.Fatalf("RemoveAgentRepo: %v", err)
	}
	if _, err := os.Stat(AgentRepoPath(base, agentID)); !os.IsNotExist(err) {
		t.Fatalf("repo dir should be gone, stat: %v", err)
	}
	// Idempotent
	if err := RemoveAgentRepo(base, agentID); err != nil {
		t.Fatalf("RemoveAgentRepo (idempotent): %v", err)
	}
}

func TestRecoverAgentRepo_ResetsToCleanMain(t *testing.T) {
	base := t.TempDir()
	agentID := "recover-x"
	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	repo := AgentRepoPath(base, agentID)

	// Commit a go.mod on main so the later edit is a tracked modification
	// (mirrors real agent repos; `checkout -f` resets tracked changes).
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module agent\n\ngo 1.26.0\n\nrequire github.com/airlockrun/agentsdk v0.2.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runGit(repo, "add", "go.mod"); err != nil {
		t.Fatal(err)
	}
	if err := runGit(repo, "commit", "-m", "add go.mod"); err != nil {
		t.Fatal(err)
	}

	// Simulate a failed build's residue: a stale upgrade branch checked
	// out, plus an uncommitted (tracked) edit to go.mod.
	if err := runGit(repo, "checkout", "-b", "upgrade/stale"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module agent\n\ngo 1.26.0\n\nrequire github.com/airlockrun/agentsdk v0.3.0-rc.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	recovered, err := RecoverAgentRepo(repo)
	if err != nil {
		t.Fatalf("RecoverAgentRepo: %v", err)
	}
	if !recovered {
		t.Error("expected recovered=true for stale-branch + dirty tree")
	}

	branch, _ := gitOutput(repo, "branch", "--show-current")
	if branch != "main" && branch != "master" {
		t.Errorf("expected to be on main after recovery, got %q", branch)
	}
	status, _ := gitOutput(repo, "status", "--porcelain")
	if strings.TrimSpace(status) != "" {
		t.Errorf("expected clean tree after recovery, got:\n%s", status)
	}
	// The stale branch is preserved for manual recovery, not deleted.
	branches, _ := gitOutput(repo, "branch", "--format=%(refname:short)")
	if !strings.Contains(branches, "upgrade/stale") {
		t.Errorf("stale upgrade branch should be preserved; branches:\n%s", branches)
	}

	// Clean repo on main → no-op.
	recovered2, err := RecoverAgentRepo(repo)
	if err != nil {
		t.Fatalf("RecoverAgentRepo (clean): %v", err)
	}
	if recovered2 {
		t.Error("expected recovered=false on an already-clean main repo")
	}
}
