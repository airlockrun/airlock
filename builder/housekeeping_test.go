package builder

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/scaffold"
)

// scaffoldHousekeepingFixture initializes a per-agent repo with a real
// scaffold (canonical airlock-managed state) and returns the repo path.
// Used by each housekeeping test as the starting point — the test then
// mutates one file and asserts runHousekeeping corrects it.
func scaffoldHousekeepingFixture(t *testing.T) (repoPath string, data scaffold.ScaffoldData) {
	t.Helper()
	base := t.TempDir()
	agentID := "11111111-2222-3333-4444-555555555555"
	if err := InitAgentRepo(base, agentID); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	repoPath = AgentRepoPath(base, agentID)
	data = scaffold.ScaffoldData{
		AgentID:         agentID,
		Module:          "agent",
		GoVersion:       buildGoVersion,
		AgentSDKVersion: "v" + agentsdk.Version,
		AgentBaseImage:  "airlock-agent-base:test",
	}
	if _, err := CommitScaffold(repoPath, data); err != nil {
		t.Fatalf("CommitScaffold: %v", err)
	}
	if err := MergeBranch(repoPath, "build/init"); err != nil {
		t.Fatalf("MergeBranch: %v", err)
	}
	return repoPath, data
}

func TestRunHousekeeping_NoopOnCurrentScaffold(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	if res.Changed() {
		t.Errorf("expected no changes on fresh scaffold, got %+v", res)
	}
}

func TestRunHousekeeping_RegeneratesStaleDockerfile(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)

	if err := os.WriteFile(filepath.Join(repoPath, "Dockerfile"),
		[]byte("# user broke this\nFROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	if !res.DockerfileChanged {
		t.Error("expected DockerfileChanged=true after writing a custom Dockerfile")
	}
	body, _ := os.ReadFile(filepath.Join(repoPath, "Dockerfile"))
	if !strings.Contains(string(body), "FROM golang:") {
		t.Errorf("Dockerfile not regenerated from template:\n%s", body)
	}
	if strings.Contains(string(body), "# user broke this") {
		t.Error("user content survived; template should have overwritten")
	}
}

func TestRunHousekeeping_AppendsMissingGitignoreLines(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)

	// Drop one of the airlock-managed lines and add a user-only entry
	// that we expect housekeeping to preserve.
	if err := os.WriteFile(filepath.Join(repoPath, ".gitignore"),
		[]byte("# my stuff\nbuild/\ngo.work\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	if !res.GitignoreChanged {
		t.Error("expected GitignoreChanged=true after dropping a managed line")
	}
	body, _ := os.ReadFile(filepath.Join(repoPath, ".gitignore"))
	for _, want := range []string{"go.work", "go.work.sum", "build/", "# my stuff"} {
		if !strings.Contains(string(body), want) {
			t.Errorf(".gitignore missing %q after housekeeping:\n%s", want, body)
		}
	}
}

func TestRunHousekeeping_GitignoreNoopWhenAlreadyHasManagedLines(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)

	// User-prepended entries plus the canonical airlock block — both
	// managed lines present, just re-ordered. Housekeeping must not
	// touch the file.
	custom := "# user stuff\nbuild/\nnode_modules/\ngo.work\ngo.work.sum\n"
	if err := os.WriteFile(filepath.Join(repoPath, ".gitignore"), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	if res.GitignoreChanged {
		t.Errorf("expected no .gitignore change; got rewrite")
	}
	body, _ := os.ReadFile(filepath.Join(repoPath, ".gitignore"))
	if string(body) != custom {
		t.Errorf(".gitignore was rewritten\nwant: %q\ngot:  %q", custom, body)
	}
}

func TestRefreshLibRequires_UpdatesPresentModule(t *testing.T) {
	ctx := context.Background()
	repoPath, _ := scaffoldHousekeepingFixture(t)

	want := map[string]string{
		// Pin to a deliberately-different version so we can assert
		// edit happened. The version doesn't need to exist on the
		// public proxy — `go mod edit` is a textual rewrite, no I/O.
		"github.com/airlockrun/agentsdk": "v9.9.9",
	}
	changed, err := refreshLibRequires(ctx, repoPath, want)
	if err != nil {
		t.Fatalf("refreshLibRequires: %v", err)
	}
	if !changed {
		t.Fatal("expected change; got false")
	}
	body, _ := os.ReadFile(filepath.Join(repoPath, "go.mod"))
	if !strings.Contains(string(body), "agentsdk v9.9.9") {
		t.Errorf("agentsdk version not updated:\n%s", body)
	}
}

func TestRefreshLibRequires_SkipsAbsentModule(t *testing.T) {
	ctx := context.Background()
	repoPath, _ := scaffoldHousekeepingFixture(t)

	// Pin a module that the scaffold doesn't import. Housekeeping must
	// NOT add it (airlock never injects a dangling require for an
	// unused module).
	want := map[string]string{
		"github.com/airlockrun/not-a-thing": "v1.0.0",
	}
	changed, err := refreshLibRequires(ctx, repoPath, want)
	if err != nil {
		t.Fatalf("refreshLibRequires: %v", err)
	}
	if changed {
		t.Error("expected no change for absent module; got rewrite")
	}
	body, _ := os.ReadFile(filepath.Join(repoPath, "go.mod"))
	if strings.Contains(string(body), "not-a-thing") {
		t.Errorf("dangling require added:\n%s", body)
	}
}

func TestRefreshLibRequires_IdempotentOnSameVersion(t *testing.T) {
	ctx := context.Background()
	repoPath, _ := scaffoldHousekeepingFixture(t)

	// Scaffold pins agentsdk at "v"+agentsdk.Version. Asking for the
	// same value must be a no-op.
	want := map[string]string{
		"github.com/airlockrun/agentsdk": "v" + agentsdk.Version,
	}
	changed, err := refreshLibRequires(ctx, repoPath, want)
	if err != nil {
		t.Fatalf("refreshLibRequires: %v", err)
	}
	if changed {
		t.Error("expected no change when version already matches")
	}
}

func TestRunHousekeeping_NoGoModSkipsSilently(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	if err := InitAgentRepo(base, "fresh-no-gomod"); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	repoPath := AgentRepoPath(base, "fresh-no-gomod")

	res, err := runHousekeeping(ctx, repoPath, scaffold.ScaffoldData{
		AgentID: "fresh-no-gomod", Module: "agent",
		GoVersion: buildGoVersion, AgentSDKVersion: "v0.0.0",
		AgentBaseImage: "base:test",
	})
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	if res.Changed() {
		t.Errorf("expected no-op on repo without go.mod, got %+v", res)
	}
}

func TestCommitHousekeeping_CommitsOnlyChangedFiles(t *testing.T) {
	repoPath, _ := scaffoldHousekeepingFixture(t)

	// Make ONLY Dockerfile dirty in the working tree, plus an
	// unrelated user file that housekeeping must NOT commit.
	if err := os.WriteFile(filepath.Join(repoPath, "Dockerfile"),
		[]byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "user-edit.go"),
		[]byte("package main // user's wip\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := commitHousekeeping(repoPath, HousekeepingResult{DockerfileChanged: true})
	if err != nil {
		t.Fatalf("commitHousekeeping: %v", err)
	}

	// HEAD commit author must be Airlock, message must mention Dockerfile.
	author, _ := gitOutput(repoPath, "log", "-1", "--format=%an")
	if author != "Airlock" {
		t.Errorf("HEAD author = %q, want Airlock", author)
	}
	msg, _ := gitOutput(repoPath, "log", "-1", "--format=%s")
	if !strings.Contains(msg, "Dockerfile") || !strings.Contains(msg, "airlock housekeeping") {
		t.Errorf("commit message = %q, want it to mention 'Dockerfile' and 'airlock housekeeping'", msg)
	}

	// The user file must remain untracked (housekeeping picks only
	// the files in the result; never `git add -A`).
	status, _ := gitOutput(repoPath, "status", "--porcelain", "user-edit.go")
	if !strings.Contains(status, "??") {
		t.Errorf("user-edit.go expected to stay untracked; got status %q", status)
	}
}

func TestCommitHousekeeping_NoChangesIsNoop(t *testing.T) {
	repoPath, _ := scaffoldHousekeepingFixture(t)
	before, _ := gitOutput(repoPath, "rev-parse", "HEAD")

	if err := commitHousekeeping(repoPath, HousekeepingResult{}); err != nil {
		t.Fatalf("commitHousekeeping: %v", err)
	}
	after, _ := gitOutput(repoPath, "rev-parse", "HEAD")
	if before != after {
		t.Errorf("HEAD moved (%s → %s) on empty result; expected no commit", before, after)
	}
}
