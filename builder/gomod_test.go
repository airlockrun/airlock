package builder

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixed go.mod body used across the cases below — mirrors the layout
// scaffold/go.mod.tmpl produces (require block + replace block).
const sampleGoMod = `module example.com/myagent

go 1.26.0

require (
	github.com/a-h/templ v0.3.865
	github.com/airlockrun/agentsdk v0.1.0
)

tool github.com/a-h/templ/cmd/templ

replace (
	github.com/airlockrun/agentsdk => /libs/agentsdk
	github.com/airlockrun/goai => /libs/goai
)
`

func writeGoMod(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return dir
}

func TestBumpAgentSDKRequire_Bumps(t *testing.T) {
	dir := writeGoMod(t, sampleGoMod)
	if err := bumpAgentSDKRequire(context.Background(), dir, "v0.2.0"); err != nil {
		t.Fatalf("bump: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "github.com/airlockrun/agentsdk v0.2.0") {
		t.Fatalf("require line not bumped:\n%s", got)
	}
	if strings.Contains(string(got), "v0.1.0") {
		t.Fatalf("old version still present:\n%s", got)
	}
	// Replace block must remain untouched — replace lines also mention
	// the import path; the regex must only match the require line.
	if !strings.Contains(string(got), "github.com/airlockrun/agentsdk => /libs/agentsdk") {
		t.Fatalf("replace directive lost:\n%s", got)
	}
}

func TestBumpAgentSDKRequire_AcceptsBareVersion(t *testing.T) {
	dir := writeGoMod(t, sampleGoMod)
	// No leading 'v' — bumpAgentSDKRequire normalizes.
	if err := bumpAgentSDKRequire(context.Background(), dir, "0.2.0"); err != nil {
		t.Fatalf("bump: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(got), "github.com/airlockrun/agentsdk v0.2.0") {
		t.Fatalf("bare version not normalized:\n%s", got)
	}
}

func TestBumpAgentSDKRequire_IdempotentAtTarget(t *testing.T) {
	dir := writeGoMod(t, sampleGoMod)
	if err := bumpAgentSDKRequire(context.Background(), dir, "v0.1.0"); err != nil {
		t.Fatalf("bump: %v", err)
	}
	// Body should be byte-identical to the input.
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if string(got) != sampleGoMod {
		t.Fatalf("expected no-op edit, got:\n%s", got)
	}
}

func TestBumpAgentSDKRequire_StandaloneRequire(t *testing.T) {
	body := `module example.com/myagent

go 1.26.0

require github.com/airlockrun/agentsdk v0.1.0
`
	dir := writeGoMod(t, body)
	if err := bumpAgentSDKRequire(context.Background(), dir, "v0.2.0"); err != nil {
		t.Fatalf("bump: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(got), "require github.com/airlockrun/agentsdk v0.2.0") {
		t.Fatalf("standalone require not bumped:\n%s", got)
	}
}

func TestBumpAgentSDKRequire_MissingRequire(t *testing.T) {
	body := `module example.com/myagent

go 1.26.0

require github.com/foo/bar v1.0.0
`
	dir := writeGoMod(t, body)
	err := bumpAgentSDKRequire(context.Background(), dir, "v0.2.0")
	if err == nil {
		t.Fatal("expected error for missing agentsdk require")
	}
	if !strings.Contains(err.Error(), "no require directive") {
		t.Fatalf("error should explain the cause, got %v", err)
	}
}
