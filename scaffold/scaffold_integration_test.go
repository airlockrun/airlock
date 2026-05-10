package scaffold

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// TestScaffoldBuildsAndStarts verifies that the scaffold output compiles
// and that the resulting binary starts and serves /health.
func TestScaffoldBuildsAndStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Read airlock's go.mod (one level up from scaffold/) to pick up the
	// agentsdk version airlock is currently pinned to. Same source of
	// truth as the drift check — the scaffolded agent compiles against
	// the exact lib version the build pipeline will use.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	airlockMod, err := os.ReadFile(filepath.Join(wd, "..", "go.mod"))
	if err != nil {
		t.Fatalf("read airlock go.mod: %v", err)
	}
	agentsdkVer := requireVersion(t, airlockMod, "github.com/airlockrun/agentsdk")
	goaiVer := requireVersion(t, airlockMod, "github.com/airlockrun/goai")
	solVer := requireVersion(t, airlockMod, "github.com/airlockrun/sol")

	// Materialize scaffold.
	dir := t.TempDir()
	data := ScaffoldData{
		AgentID:         "test-agent-build",
		Module:          "agent",
		GoVersion:       "1.26",
		AgentSDKVersion: "v1.0.0",
		AgentBaseImage:  "airlock-agent-base",
	}
	if err := Materialize(dir, data); err != nil {
		t.Fatalf("Materialize: %v", err)
	}

	// Overwrite go.mod — the template's version is targeted at the prod
	// Docker layout (/libs/* replaces). Here we resolve through the public
	// proxy at the same agentsdk version airlock pins, so the test
	// validates exactly what the build pipeline will compile.
	// Pin agentsdk + goai + sol explicitly so MVS doesn't pick up stale
	// sub-pins from a published agentsdk's go.mod (e.g. agentsdk@v0.2.4
	// still requires sol v0.1.0 because the workspace masked the bump
	// at tag time). This mirrors how airlock's own go.mod overrides
	// transitive sub-pins, ensuring the scaffold compiles against the
	// same set of versions the build pipeline will use.
	goMod := fmt.Sprintf(
		"module agent\n\ngo 1.26.0\n\nrequire (\n\tgithub.com/a-h/templ v0.3.865\n\tgithub.com/airlockrun/agentsdk %s\n\tgithub.com/airlockrun/goai %s\n\tgithub.com/airlockrun/sol %s\n)\n",
		agentsdkVer, goaiVer, solVer,
	)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}

	// Disable any ambient go.work (the hq monorepo has one) so resolution
	// goes purely through go.mod + the proxy. CI doesn't have a workspace
	// either, this keeps the two paths identical.
	env := append(os.Environ(), "GOWORK=off")

	// `go build` won't auto-populate go.sum; tidy first.
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	tidy.Env = env
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy failed:\n%s", out)
	}

	// --- Step 1: Generate templ + Build ---
	templGen := exec.Command("templ", "generate")
	templGen.Dir = dir
	templGen.Env = env
	if out, err := templGen.CombinedOutput(); err != nil {
		t.Fatalf("templ generate failed:\n%s", out)
	}

	binPath := filepath.Join(dir, "agent")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = dir
	build.Env = env
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed:\n%s", out)
	}

	// --- Step 2: Start with mock Airlock ---
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Sync endpoint needs a valid JSON response; others just need 200.
		if r.URL.Path == "/api/agent/sync" {
			w.Write([]byte(`{"systemPrompt":"test"}`))
		} else {
			w.Write([]byte(`{}`))
		}
	}))
	defer mock.Close()

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	cmd := exec.Command(binPath)
	cmd.Env = []string{
		"AIRLOCK_AGENT_ID=test-agent",
		"AIRLOCK_API_URL=" + mock.URL,
		"AIRLOCK_AGENT_TOKEN=test-token",
		"AIRLOCK_ADDR=" + addr,
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer cmd.Process.Kill()

	// Poll /health until it responds or times out.
	healthURL := fmt.Sprintf("http://%s/health", addr)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		var body struct {
			Status string `json:"status"`
		}
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if body.Status != "ok" {
			t.Fatalf("expected status ok, got %q", body.Status)
		}
		return // success
	}
	t.Fatal("agent did not start within 5 seconds")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// requireVersion extracts the version pin for `module` from a go.mod
// file's bytes. Matches both `require <module> <ver>` and the parenthesized
// `require ( ... <module> <ver> ... )` form.
func requireVersion(t *testing.T, modBytes []byte, module string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^[\t ]*` + regexp.QuoteMeta(module) + `[\t ]+(\S+)`)
	m := re.FindSubmatch(modBytes)
	if len(m) < 2 {
		t.Fatalf("go.mod: no require entry for %s", module)
	}
	return string(m[1])
}
