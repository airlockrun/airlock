package builder

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/scaffold"
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

func TestRunHousekeeping_RegeneratesStaleAgentsMD(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)

	if err := os.WriteFile(filepath.Join(repoPath, "AGENTS.md"),
		[]byte("# user clobbered the docs\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	if !res.AgentsMDChanged {
		t.Error("expected AgentsMDChanged=true after editing AGENTS.md")
	}
	body, _ := os.ReadFile(filepath.Join(repoPath, "AGENTS.md"))
	if !strings.Contains(string(body), "how this agent is built") {
		t.Errorf("AGENTS.md not regenerated from template:\n%s", body)
	}
	if strings.Contains(string(body), "# user clobbered the docs") {
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
	for _, want := range append([]string{"go.work", "go.work.sum", ".airlock/local/", ".airlock/toolchain/", "build/", "# my stuff"}, scaffold.GeneratedArtifactIgnorePatterns()...) {
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
	custom := "# user stuff\nbuild/\nnode_modules/\ngo.work\ngo.work.sum\n.airlock/local/\n.airlock/toolchain/\n" + strings.Join(scaffold.GeneratedArtifactIgnorePatterns(), "\n") + "\n"
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

func TestRunHousekeeping_StripsDockerfileFromGitignore(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)

	// Old InitAgentRepo wrote a .gitignore listing Dockerfile; that blocks
	// committing the now-committed Dockerfile. Housekeeping must drop it.
	if err := os.WriteFile(filepath.Join(repoPath, ".gitignore"),
		[]byte("DIAGNOSTICS.md\nDockerfile\ngo.work\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	if !res.GitignoreChanged {
		t.Error("expected GitignoreChanged=true after stale Dockerfile entry")
	}
	body, _ := os.ReadFile(filepath.Join(repoPath, ".gitignore"))
	s := string(body)
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "Dockerfile" {
			t.Errorf("Dockerfile still ignored:\n%s", s)
		}
	}
	// User-authored + managed entries preserved.
	for _, want := range []string{"DIAGNOSTICS.md", "go.work", "go.work.sum"} {
		if !strings.Contains(s, want) {
			t.Errorf(".gitignore missing %q:\n%s", want, s)
		}
	}
	// And `git add Dockerfile` now works (the original failure).
	if err := os.WriteFile(filepath.Join(repoPath, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := git(repoPath, "add", "--", "Dockerfile"); err != nil {
		t.Errorf("git add Dockerfile failed after gitignore reconcile: %v", err)
	}
}

func TestRunHousekeeping_RemovesStaleGoWork(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)

	// A leftover go.work (gitignored) from an older build would otherwise
	// ride into the build context via `COPY . .` and break `go mod tidy`.
	for _, f := range []string{"go.work", "go.work.sum"} {
		if err := os.WriteFile(filepath.Join(repoPath, f), []byte("go 1.26.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := runHousekeeping(ctx, repoPath, data); err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	for _, f := range []string{"go.work", "go.work.sum"} {
		if _, err := os.Stat(filepath.Join(repoPath, f)); !os.IsNotExist(err) {
			t.Errorf("%s still present after housekeeping (err=%v)", f, err)
		}
	}
}

func TestRunHousekeeping_BumpsStaleAgentSDKRequire(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)

	// Rewrite the agentsdk require to an old version so housekeeping has
	// something to correct back to the current const.
	gomod := filepath.Join(repoPath, "go.mod")
	body, _ := os.ReadFile(gomod)
	stale := strings.Replace(string(body), "agentsdk v"+agentsdk.Version, "agentsdk v0.0.1", 1)
	if stale == string(body) {
		t.Fatalf("fixture go.mod didn't contain agentsdk v%s:\n%s", agentsdk.Version, body)
	}
	if err := os.WriteFile(gomod, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	if !res.GoModChanged {
		t.Error("expected GoModChanged=true after staling the agentsdk require")
	}
	after, _ := os.ReadFile(gomod)
	if !strings.Contains(string(after), "agentsdk v"+agentsdk.Version) {
		t.Errorf("agentsdk require not bumped back to const v%s:\n%s", agentsdk.Version, after)
	}
}

func TestRunHousekeeping_AddsBuildToolDirectives(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)
	gomod := filepath.Join(repoPath, "go.mod")
	body, err := os.ReadFile(gomod)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range agentModuleTools {
		body = []byte(strings.ReplaceAll(string(body), "tool "+tool+"\n", ""))
	}
	if err := os.WriteFile(gomod, body, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	if !res.GoModChanged {
		t.Fatal("expected GoModChanged=true")
	}
	after, err := os.ReadFile(gomod)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range agentModuleTools {
		if !strings.Contains(string(after), tool) {
			t.Errorf("go.mod missing tool %s:\n%s", tool, after)
		}
	}
}

func TestRunHousekeeping_RemovesTrackedGeneratedArtifacts(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)
	generated := map[string]string{
		"agent":                  "binary",
		"internal/db/models.go":  "// Code generated by sqlc. DO NOT EDIT.\n",
		"internal/db/queries.go": "// Code generated by sqlc. DO NOT EDIT.\n",
		"views/index_templ.go":   "// Code generated by templ - DO NOT EDIT.\n",
		"views/static/app.css":   "generated css",
		"internal/db/doc.go":     "package db\n",
	}
	for rel, body := range generated {
		path := filepath.Join(repoPath, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := git(repoPath, "add", "-f", "--", rel); err != nil {
			t.Fatal(err)
		}
	}
	if err := git(repoPath, "commit", "-m", "add generated templ output"); err != nil {
		t.Fatal(err)
	}

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatalf("runHousekeeping: %v", err)
	}
	wantRemoved := []string{"agent", "internal/db/models.go", "internal/db/queries.go", "views/index_templ.go", "views/static/app.css"}
	if strings.Join(res.GeneratedFilesRemoved, "\n") != strings.Join(wantRemoved, "\n") {
		t.Fatalf("GeneratedFilesRemoved = %#v", res.GeneratedFilesRemoved)
	}
	for _, rel := range wantRemoved {
		if _, err := os.Stat(filepath.Join(repoPath, filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Fatalf("generated artifact %s still exists: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(repoPath, "internal", "db", "doc.go")); err != nil {
		t.Fatalf("internal/db/doc.go was not preserved: %v", err)
	}
	if err := commitHousekeeping(repoPath, res); err != nil {
		t.Fatalf("commitHousekeeping: %v", err)
	}
	tracked, err := gitOutput(repoPath, "ls-files", "--", "agent", "internal/db/models.go", "internal/db/queries.go", "views/index_templ.go", "views/static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	if tracked != "" {
		t.Fatalf("generated artifacts remain tracked: %s", tracked)
	}
}

func TestRunHousekeeping_NewerCompatibleSDKOwnsManagedFiles(t *testing.T) {
	ctx := context.Background()
	repoPath, data := scaffoldHousekeepingFixture(t)
	gomod := filepath.Join(repoPath, "go.mod")
	body, _ := os.ReadFile(gomod)
	body = []byte(strings.Replace(string(body), "agentsdk v"+agentsdk.Version, "agentsdk v0.4.0-rc.20", 1))
	if err := os.WriteFile(gomod, body, 0o644); err != nil {
		t.Fatal(err)
	}
	data.AgentSDKVersion = "v0.4.0-rc.18"
	dockerfile := filepath.Join(repoPath, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("newer managed Dockerfile\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	goWork := filepath.Join(repoPath, "go.work")
	if err := os.WriteFile(goWork, []byte("go 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runHousekeeping(ctx, repoPath, data)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed() {
		t.Fatalf("older Airlock changed newer managed source: %+v", res)
	}
	if got, _ := os.ReadFile(dockerfile); string(got) != "newer managed Dockerfile\n" {
		t.Fatalf("Dockerfile was rewritten by older Airlock:\n%s", got)
	}
	if got, _ := os.ReadFile(gomod); !strings.Contains(string(got), "agentsdk v0.4.0-rc.20") {
		t.Fatalf("newer SDK requirement was rewritten:\n%s", got)
	}
	if _, err := os.Stat(goWork); !os.IsNotExist(err) {
		t.Fatalf("local go.work was not removed: %v", err)
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
		AgentID:   "fresh-no-gomod",
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

func TestCommitHousekeepingConfiguresMissingIdentity(t *testing.T) {
	repoPath, _ := scaffoldHousekeepingFixture(t)
	unsetGitIdentity(repoPath)

	if err := os.WriteFile(filepath.Join(repoPath, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := commitHousekeeping(repoPath, HousekeepingResult{DockerfileChanged: true}); err != nil {
		t.Fatalf("commitHousekeeping: %v", err)
	}
	name, err := gitOutput(repoPath, "config", "--local", "user.name")
	if err != nil {
		t.Fatalf("git config user.name: %v", err)
	}
	if name != gitUserName {
		t.Fatalf("user.name = %q, want %q", name, gitUserName)
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
