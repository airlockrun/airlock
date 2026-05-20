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

func TestCloneAgentRepo(t *testing.T) {
	base := t.TempDir()
	agentID := "clone-agent"
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

	checkoutDir := filepath.Join(t.TempDir(), "checkout")
	mainBranch := "main"
	if err := CloneAgentRepo(repoPath, mainBranch, checkoutDir); err != nil {
		mainBranch = "master"
		if err2 := CloneAgentRepo(repoPath, mainBranch, checkoutDir); err2 != nil {
			t.Fatalf("CloneAgentRepo: main=%v, master=%v", err, err2)
		}
	}

	if _, err := os.Stat(filepath.Join(checkoutDir, "main.go")); err != nil {
		t.Fatal("main.go not found at clone root")
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

func TestCommitAndPush(t *testing.T) {
	base := t.TempDir()
	agentID := "push-agent"
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

	checkoutDir := filepath.Join(t.TempDir(), "checkout")
	branch := "main"
	if err := CloneAgentRepo(repoPath, branch, checkoutDir); err != nil {
		branch = "master"
		if err2 := CloneAgentRepo(repoPath, branch, checkoutDir); err2 != nil {
			t.Fatalf("CloneAgentRepo: %v", err2)
		}
	}

	if err := os.WriteFile(filepath.Join(checkoutDir, "test.txt"), []byte("test content"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	hash, err := CommitAndPush(checkoutDir, "add test file")
	if err != nil {
		t.Fatalf("CommitAndPush: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty commit hash")
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
