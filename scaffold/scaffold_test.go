package scaffold

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterialize(t *testing.T) {
	dir := t.TempDir()

	data := ScaffoldData{
		AgentID:         "550e8400-e29b-41d4-a716-446655440000",
		Module:          "github.com/airlockrun/agents/550e8400-e29b-41d4-a716-446655440000",
		GoVersion:       "1.26",
		AgentSDKVersion: "v1.0.0",
		AgentBaseImage:  "airlock-agent-base",
	}

	if err := Materialize(dir, data); err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	// Verify all expected files exist
	expectedFiles := []string{
		"main.go",
		"go.mod",
		"sqlc.yaml",
		"Dockerfile",
		".gitignore",
	}
	for _, f := range expectedFiles {
		path := filepath.Join(dir, f)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file %s not found: %v", f, err)
		}
	}

	// Verify empty directories exist
	expectedDirs := []string{
		"db/migrations",
		"db/queries",
	}
	for _, d := range expectedDirs {
		path := filepath.Join(dir, d)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected dir %s not found: %v", d, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s is not a directory", d)
		}
	}

	// Verify main.go content
	mainGo, err := os.ReadFile(filepath.Join(dir, "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if !strings.Contains(string(mainGo), "agentsdk.New(agentsdk.Config{") {
		t.Error("main.go missing agentsdk.New(agentsdk.Config{)")
	}
	if !strings.Contains(string(mainGo), "agent.Serve()") {
		t.Error("main.go missing agent.Serve()")
	}

	// Committed go.mod has no /libs/... replace block — those live only
	// in the build-time go.work that airlock injects into codegen and
	// docker contexts. Keeping replaces out of the committed file lets
	// user clones compile against public modules.
	goMod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	goModStr := string(goMod)
	if !strings.Contains(goModStr, data.Module) {
		t.Error("go.mod missing module path")
	}
	for _, unwanted := range []string{"/libs/agentsdk", "/libs/goai", "/libs/sol", "/libs/goose", "/libs/templ"} {
		if strings.Contains(goModStr, unwanted) {
			t.Errorf("go.mod must not contain %s replace directive (build-time go.work supplies it)", unwanted)
		}
	}
	if !strings.Contains(goModStr, "agentsdk v1.0.0") {
		t.Errorf("go.mod should pin agentsdk to AgentSDKVersion (v1.0.0); got:\n%s", goModStr)
	}

	// .gitignore lists the build-time-only files airlock generates
	// (go.work pair). Dockerfile is committed so users can build the
	// container locally; airlock-side builds regenerate it into a temp
	// dir and use `docker build -f` to avoid touching the committed copy.
	gitignore, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	for _, want := range []string{"go.work", "go.work.sum"} {
		if !strings.Contains(string(gitignore), want) {
			t.Errorf(".gitignore missing %q entry", want)
		}
	}
	if strings.Contains(string(gitignore), "Dockerfile") {
		t.Error(".gitignore must not list Dockerfile (committed for local-build support)")
	}

	// Dockerfile must always have COPY --from=libs (unconditional) and use
	// the agent-base runtime + dep hooks.
	if err := GenerateDockerfile(dir, data); err != nil {
		t.Fatalf("GenerateDockerfile: %v", err)
	}
	dockerfile, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	dockerfileStr := string(dockerfile)
	if !strings.Contains(dockerfileStr, "golang:1.26") {
		t.Error("Dockerfile missing golang version")
	}
	if !strings.Contains(dockerfileStr, "airlock-agent-base") {
		t.Error("Dockerfile missing agent base image")
	}
	if !strings.Contains(dockerfileStr, "--from=libs") {
		t.Error("Dockerfile must always have --from=libs")
	}
	if !strings.Contains(dockerfileStr, "setup.sh") {
		t.Error("Dockerfile missing setup.sh hook")
	}
	if !strings.Contains(dockerfileStr, "type=cache,target=/var/lib/apt/lists") {
		t.Error("Dockerfile missing apt cache mount")
	}
}

func TestMaterialize_RequiresSDKVersion(t *testing.T) {
	dir := t.TempDir()

	// Missing AgentSDKVersion → fail loud (go.mod would otherwise render
	// with an empty version and produce invalid Go module syntax).
	err := Materialize(dir, ScaffoldData{
		AgentID:   "550e8400-e29b-41d4-a716-446655440000",
		Module:    "agent",
		GoVersion: "1.26",
	})
	if err == nil {
		t.Fatal("expected error when AgentSDKVersion is empty")
	}
	if !strings.Contains(err.Error(), "AgentSDKVersion") {
		t.Fatalf("error = %v, want mention of AgentSDKVersion", err)
	}
}
