package builder

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk/scaffold"
)

// fixed go.mod body used across the cases below. The replace block verifies
// that module reconciliation only changes managed requirements and tools.
const sampleGoMod = `module example.com/myagent

go 1.26.0

require (
	github.com/a-h/templ v0.3.1020
	github.com/airlockrun/agentsdk v0.1.0
)

tool github.com/a-h/templ/cmd/templ

tool github.com/airlockrun/agentsdk/cmd/air

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

func TestReconcileAgentGoMod_Bumps(t *testing.T) {
	dir := writeGoMod(t, sampleGoMod)
	if err := reconcileAgentGoMod(context.Background(), dir, "v0.2.0"); err != nil {
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

func TestReconcileAgentGoMod_AcceptsBareVersion(t *testing.T) {
	dir := writeGoMod(t, sampleGoMod)
	// No leading 'v' — reconcileAgentGoMod normalizes.
	if err := reconcileAgentGoMod(context.Background(), dir, "0.2.0"); err != nil {
		t.Fatalf("bump: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(got), "github.com/airlockrun/agentsdk v0.2.0") {
		t.Fatalf("bare version not normalized:\n%s", got)
	}
}

func TestReconcileAgentGoMod_IdempotentAtTarget(t *testing.T) {
	dir := writeGoMod(t, sampleGoMod)
	if err := reconcileAgentGoMod(context.Background(), dir, "v0.1.0"); err != nil {
		t.Fatalf("bump: %v", err)
	}
	// Body should be byte-identical to the input.
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if string(got) != sampleGoMod {
		t.Fatalf("expected no-op edit, got:\n%s", got)
	}
}

func TestReconcileAgentGoMod_PreservesNewerCompatibleVersion(t *testing.T) {
	body := strings.Replace(sampleGoMod, "agentsdk v0.1.0", "agentsdk v0.4.0-rc.20", 1)
	dir := writeGoMod(t, body)
	if err := reconcileAgentGoMod(context.Background(), dir, "v0.4.0-rc.18"); err != nil {
		t.Fatalf("bump: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if string(got) != body {
		t.Fatalf("newer compatible requirement was rewritten:\n%s", got)
	}
}

func TestReconcileAgentGoMod_UpgradesOlderCompatibleVersion(t *testing.T) {
	body := strings.Replace(sampleGoMod, "agentsdk v0.1.0", "agentsdk v0.4.0-rc.18", 1)
	dir := writeGoMod(t, body)
	if err := reconcileAgentGoMod(context.Background(), dir, "v0.4.0-rc.20"); err != nil {
		t.Fatalf("bump: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(got), "agentsdk v0.4.0-rc.20") {
		t.Fatalf("older compatible requirement not upgraded:\n%s", got)
	}
}

func TestReconcileAgentGoMod_DevVersionIsExact(t *testing.T) {
	body := strings.Replace(sampleGoMod, "agentsdk v0.1.0", "agentsdk v0.4.0-rc.21", 1)
	dir := writeGoMod(t, body)
	want := "v0.4.0-rc.20-devabc123"
	if err := reconcileAgentGoMod(context.Background(), dir, want); err != nil {
		t.Fatalf("bump: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(got), "agentsdk "+want) {
		t.Fatalf("development requirement not pinned exactly:\n%s", got)
	}
}

func TestCompatibleAgentSDKRequire(t *testing.T) {
	tests := []struct {
		current string
		target  string
		want    bool
	}{
		{current: "v0.4.0-rc.20", target: "v0.4.0-rc.18", want: true},
		{current: "v0.4.1", target: "v0.4.0", want: true},
		{current: "v0.4.0-rc.18", target: "v0.4.0-rc.20", want: false},
		{current: "v0.5.0", target: "v0.4.9", want: false},
		{current: "invalid", target: "v0.4.0", want: false},
	}
	for _, tt := range tests {
		name := tt.current + "_to_" + tt.target
		t.Run(name, func(t *testing.T) {
			if got := compatibleAgentSDKRequire(tt.current, tt.target); got != tt.want {
				t.Errorf("compatibleAgentSDKRequire(%q, %q) = %v, want %v", tt.current, tt.target, got, tt.want)
			}
		})
	}
}

func TestNewerCompatibleAgentSDKRequire(t *testing.T) {
	tests := []struct {
		current string
		target  string
		want    bool
	}{
		{current: "v0.4.0-rc.20", target: "v0.4.0-rc.18", want: true},
		{current: "v0.4.1", target: "v0.4.0", want: true},
		{current: "v0.4.0-rc.20", target: "v0.4.0-rc.20", want: false},
		{current: "v0.4.0-rc.18", target: "v0.4.0-rc.20", want: false},
		{current: "v0.5.0", target: "v0.4.9", want: false},
		{current: "v0.4.0-rc.21", target: "v0.4.0-rc.20-devabc", want: false},
	}
	for _, tt := range tests {
		name := tt.current + "_over_" + tt.target
		t.Run(name, func(t *testing.T) {
			if got := newerCompatibleAgentSDKRequire(tt.current, tt.target); got != tt.want {
				t.Errorf("newerCompatibleAgentSDKRequire(%q, %q) = %v, want %v", tt.current, tt.target, got, tt.want)
			}
		})
	}
}

func TestReconcileAgentGoMod_StandaloneRequire(t *testing.T) {
	body := `module example.com/myagent

go 1.26.0

require github.com/airlockrun/agentsdk v0.1.0
`
	dir := writeGoMod(t, body)
	if err := reconcileAgentGoMod(context.Background(), dir, "v0.2.0"); err != nil {
		t.Fatalf("bump: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
	if !strings.Contains(string(got), "github.com/airlockrun/agentsdk v0.2.0") {
		t.Fatalf("standalone require not bumped:\n%s", got)
	}
}

func TestReconcileAgentGoMod_MissingRequire(t *testing.T) {
	body := `module example.com/myagent

go 1.26.0

require github.com/foo/bar v1.0.0
`
	dir := writeGoMod(t, body)
	err := reconcileAgentGoMod(context.Background(), dir, "v0.2.0")
	if err == nil {
		t.Fatal("expected error for missing agentsdk require")
	}
	if !strings.Contains(err.Error(), "no require directive") {
		t.Fatalf("error should explain the cause, got %v", err)
	}
}

func TestReconcileAgentGoMod_AddsBuildTools(t *testing.T) {
	body := strings.ReplaceAll(sampleGoMod, "\ntool github.com/a-h/templ/cmd/templ\n", "")
	body = strings.ReplaceAll(body, "\ntool github.com/airlockrun/agentsdk/cmd/air\n", "")
	dir := writeGoMod(t, body)
	if err := reconcileAgentGoMod(context.Background(), dir, "v0.1.0"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range agentModuleTools {
		if !strings.Contains(string(got), tool) {
			t.Errorf("go.mod missing tool %s:\n%s", tool, got)
		}
	}
}

func TestReconcileAgentGoMod_PinsScaffoldVersions(t *testing.T) {
	body := strings.Replace(sampleGoMod, "go 1.26.0", "go 1.25.0", 1)
	body = strings.Replace(body, "github.com/a-h/templ "+scaffold.TemplVersion, "github.com/a-h/templ "+"v0."+"2.0", 1)
	dir := writeGoMod(t, body)
	if err := reconcileAgentGoMod(context.Background(), dir, "v0.1.0"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"go " + scaffold.GoVersion,
		"github.com/a-h/templ " + scaffold.TemplVersion,
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("go.mod missing %q:\n%s", want, got)
		}
	}
}
