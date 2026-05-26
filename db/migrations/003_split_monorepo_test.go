package migrations

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// initAgentRepo creates a per-agent repo fixture with a go.mod that
// contains the libs replace block (mimics pre-cleanup state).
func initAgentRepo(t *testing.T, base, agentID string, withReplaces bool) string {
	t.Helper()
	dir := filepath.Join(base, agentID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ctx := context.Background()

	if err := gitRun(ctx, dir, "init", "-b", "main"); err != nil {
		t.Fatalf("git init: %v", err)
	}
	if err := gitRun(ctx, dir, "config", "user.email", "test@example.com"); err != nil {
		t.Fatalf("git config email: %v", err)
	}
	if err := gitRun(ctx, dir, "config", "user.name", "Test"); err != nil {
		t.Fatalf("git config name: %v", err)
	}

	var goMod string
	if withReplaces {
		goMod = `module agent

go 1.26

require github.com/airlockrun/agentsdk v0.1.0

replace (
	github.com/airlockrun/agentsdk => /libs/agentsdk
	github.com/airlockrun/goai => /libs/goai
	github.com/airlockrun/sol => /libs/sol
	github.com/pressly/goose/v3 => /libs/goose
	github.com/a-h/templ => /libs/templ
)
`
	} else {
		// "Already clean" agent: no replaces, .gitignore already present.
		goMod = `module agent

go 1.26

require github.com/airlockrun/agentsdk v0.1.0
`
		if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignoreContent), 0o644); err != nil {
			t.Fatalf("seed gitignore: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	if err := gitRun(ctx, dir, "add", "-A"); err != nil {
		t.Fatalf("git add: %v", err)
	}
	if err := gitRun(ctx, dir, "commit", "-m", "initial"); err != nil {
		t.Fatalf("git commit: %v", err)
	}
	return dir
}

func commitCount(t *testing.T, dir string) int {
	t.Helper()
	out, err := gitOutput(context.Background(), dir, "rev-list", "--count", "HEAD")
	if err != nil {
		t.Fatalf("rev-list: %v", err)
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "%d", &n); err != nil {
		t.Fatalf("parse commit count %q: %v", out, err)
	}
	return n
}

func TestUpStripLibsReplaces(t *testing.T) {
	base := t.TempDir()
	t.Setenv("AGENT_REPOS_PATH", base)

	dirty := initAgentRepo(t, base, "11111111-1111-1111-1111-111111111111", true)
	clean := initAgentRepo(t, base, "22222222-2222-2222-2222-222222222222", false)

	cleanCommitsBefore := commitCount(t, clean)
	dirtyCommitsBefore := commitCount(t, dirty)

	if err := upStripLibsReplaces(context.Background(), nil); err != nil {
		t.Fatalf("upStripLibsReplaces: %v", err)
	}

	// Dirty repo: should have one new commit + go.mod cleaned + .gitignore present.
	if got := commitCount(t, dirty); got != dirtyCommitsBefore+1 {
		t.Errorf("dirty repo commit count = %d, want %d", got, dirtyCommitsBefore+1)
	}
	goMod, err := os.ReadFile(filepath.Join(dirty, "go.mod"))
	if err != nil {
		t.Fatalf("read dirty go.mod: %v", err)
	}
	for _, unwanted := range []string{"/libs/agentsdk", "/libs/goai", "/libs/sol", "/libs/goose", "/libs/templ"} {
		if strings.Contains(string(goMod), unwanted) {
			t.Errorf("dirty go.mod still contains %q after migration", unwanted)
		}
	}
	gi, err := os.ReadFile(filepath.Join(dirty, ".gitignore"))
	if err != nil {
		t.Fatalf("read dirty .gitignore: %v", err)
	}
	for _, want := range []string{"Dockerfile", "go.work", "go.work.sum"} {
		if !strings.Contains(string(gi), want) {
			t.Errorf("dirty .gitignore missing %q", want)
		}
	}

	// Clean repo: no new commit.
	if got := commitCount(t, clean); got != cleanCommitsBefore {
		t.Errorf("clean repo commit count = %d, want unchanged %d", got, cleanCommitsBefore)
	}

	// Idempotent: re-run yields no further commits anywhere.
	dirtyAfter := commitCount(t, dirty)
	if err := upStripLibsReplaces(context.Background(), nil); err != nil {
		t.Fatalf("second up: %v", err)
	}
	if got := commitCount(t, dirty); got != dirtyAfter {
		t.Errorf("re-run created %d extra commit(s); migration not idempotent", got-dirtyAfter)
	}
}

func TestUpStripLibsReplaces_NoBaseDir(t *testing.T) {
	t.Setenv("AGENT_REPOS_PATH", filepath.Join(t.TempDir(), "does-not-exist"))
	if err := upStripLibsReplaces(context.Background(), nil); err != nil {
		t.Fatalf("fresh install (missing base) should be no-op, got: %v", err)
	}
}
