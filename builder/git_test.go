package builder

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/scaffold"
)

func TestInitMonorepo(t *testing.T) {
	dir := t.TempDir()
	repoPath := filepath.Join(dir, "repo")

	if err := InitMonorepo(repoPath); err != nil {
		t.Fatalf("InitMonorepo: %v", err)
	}

	// Verify .git exists
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err != nil {
		t.Fatal(".git directory not found")
	}

	// Verify we're on main (or master)
	branch, err := gitOutput(repoPath, "branch", "--show-current")
	if err != nil {
		t.Fatalf("get branch: %v", err)
	}
	if branch != "main" && branch != "master" {
		t.Fatalf("expected main or master, got %q", branch)
	}

	// Verify initial commit exists
	log, err := gitOutput(repoPath, "log", "--oneline")
	if err != nil {
		t.Fatalf("git log: %v", err)
	}
	if !strings.Contains(log, "init") {
		t.Fatalf("expected init commit, got %q", log)
	}

	// Idempotent — should not error on second call
	if err := InitMonorepo(repoPath); err != nil {
		t.Fatalf("InitMonorepo (idempotent): %v", err)
	}
}

func TestCommitScaffold(t *testing.T) {
	dir := t.TempDir()
	repoPath := filepath.Join(dir, "repo")

	if err := InitMonorepo(repoPath); err != nil {
		t.Fatalf("InitMonorepo: %v", err)
	}

	agentID := "test-agent-id"
	data := scaffold.ScaffoldData{
		AgentID:   agentID,
		Module:    "agent",
		GoVersion:       "1.25",
		AgentSDKVersion: "v1.0.0",
	}

	hash, err := CommitScaffold(repoPath, agentID, data)
	if err != nil {
		t.Fatalf("CommitScaffold: %v", err)
	}

	if hash == "" {
		t.Fatal("expected non-empty commit hash")
	}

	// Verify branch exists
	branch := "build/" + agentID + "/init"
	branches, err := gitOutput(repoPath, "branch")
	if err != nil {
		t.Fatalf("git branch: %v", err)
	}
	if !strings.Contains(branches, branch) {
		t.Fatalf("branch %q not found in: %s", branch, branches)
	}

	// Verify files exist
	mainGo := filepath.Join(repoPath, "agents", agentID, "main.go")
	if _, err := os.Stat(mainGo); err != nil {
		t.Fatal("main.go not found after scaffold")
	}
}

func TestSparseCheckout(t *testing.T) {
	// Skip if git version doesn't support sparse-checkout
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not in PATH")
	}

	dir := t.TempDir()
	repoPath := filepath.Join(dir, "repo")

	if err := InitMonorepo(repoPath); err != nil {
		t.Fatalf("InitMonorepo: %v", err)
	}

	agentID := "sparse-test-agent"
	data := scaffold.ScaffoldData{
		AgentID:   agentID,
		Module:    "agent",
		GoVersion:       "1.25",
		AgentSDKVersion: "v1.0.0",
	}

	_, err := CommitScaffold(repoPath, agentID, data)
	if err != nil {
		t.Fatalf("CommitScaffold: %v", err)
	}

	// Merge to main so sparse checkout can use it
	if err := MergeBranch(repoPath, "build/"+agentID+"/init"); err != nil {
		t.Fatalf("MergeBranch: %v", err)
	}

	// Sparse checkout into a new directory
	checkoutDir := filepath.Join(dir, "checkout")
	if err := SparseCheckout(repoPath, "main", agentID, checkoutDir); err != nil {
		// Try master if main fails
		if err2 := SparseCheckout(repoPath, "master", agentID, checkoutDir); err2 != nil {
			t.Fatalf("SparseCheckout: main=%v, master=%v", err, err2)
		}
	}

	// Verify agent files exist in checkout
	mainGo := filepath.Join(checkoutDir, "agents", agentID, "main.go")
	if _, err := os.Stat(mainGo); err != nil {
		t.Fatal("main.go not found in sparse checkout")
	}
}

func TestMergeBranch(t *testing.T) {
	dir := t.TempDir()
	repoPath := filepath.Join(dir, "repo")

	if err := InitMonorepo(repoPath); err != nil {
		t.Fatalf("InitMonorepo: %v", err)
	}

	agentID := "merge-test-agent"
	data := scaffold.ScaffoldData{
		AgentID:   agentID,
		Module:    "agent",
		GoVersion:       "1.25",
		AgentSDKVersion: "v1.0.0",
	}

	_, err := CommitScaffold(repoPath, agentID, data)
	if err != nil {
		t.Fatalf("CommitScaffold: %v", err)
	}

	branch := "build/" + agentID + "/init"
	if err := MergeBranch(repoPath, branch); err != nil {
		t.Fatalf("MergeBranch: %v", err)
	}

	// Verify we're on main and files exist
	currentBranch, err := gitOutput(repoPath, "branch", "--show-current")
	if err != nil {
		t.Fatalf("get branch: %v", err)
	}
	if currentBranch != "main" && currentBranch != "master" {
		t.Fatalf("expected main or master after merge, got %q", currentBranch)
	}

	mainGo := filepath.Join(repoPath, "agents", agentID, "main.go")
	if _, err := os.Stat(mainGo); err != nil {
		t.Fatal("main.go not found on main after merge")
	}
}

func TestCommitAndPush(t *testing.T) {
	dir := t.TempDir()
	repoPath := filepath.Join(dir, "repo")

	if err := InitMonorepo(repoPath); err != nil {
		t.Fatalf("InitMonorepo: %v", err)
	}

	agentID := "push-test-agent"
	data := scaffold.ScaffoldData{
		AgentID:   agentID,
		Module:    "agent",
		GoVersion:       "1.25",
		AgentSDKVersion: "v1.0.0",
	}

	_, err := CommitScaffold(repoPath, agentID, data)
	if err != nil {
		t.Fatalf("CommitScaffold: %v", err)
	}

	// Merge so main has the scaffold
	if err := MergeBranch(repoPath, "build/"+agentID+"/init"); err != nil {
		t.Fatalf("MergeBranch: %v", err)
	}

	// Sparse checkout
	checkoutDir := filepath.Join(dir, "checkout")
	branch := "main"
	if err := SparseCheckout(repoPath, branch, agentID, checkoutDir); err != nil {
		branch = "master"
		if err2 := SparseCheckout(repoPath, branch, agentID, checkoutDir); err2 != nil {
			t.Fatalf("SparseCheckout: %v", err2)
		}
	}

	// Make a change
	testFile := filepath.Join(checkoutDir, "agents", agentID, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Commit and push
	hash, err := CommitAndPush(checkoutDir, "add test file")
	if err != nil {
		t.Fatalf("CommitAndPush: %v", err)
	}

	if hash == "" {
		t.Fatal("expected non-empty commit hash")
	}
}
