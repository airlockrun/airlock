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
	"testing"
	"time"
)

// TestScaffoldBuildsAndStarts verifies that the scaffold output compiles
// and that the resulting binary starts and serves /health.
func TestScaffoldBuildsAndStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Repo root is two levels up from airlock/scaffold/.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Join(wd, "..", "..")

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

	// Overwrite go.mod — the template uses Docker paths (/libs/...).
	// In workspace mode, go.work resolves all workspace modules without
	// require directives (adding require v0.0.0 causes Go to hit the
	// network to verify the version).
	goMod := "module agent\n\ngo 1.26.0\n\nrequire github.com/a-h/templ v0.3.865\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create go.work pointing to local workspace modules.
	goWork := fmt.Sprintf("go 1.26.0\n\nuse (\n\t.\n\t%s\n\t%s\n\t%s\n\t%s\n)\n",
		filepath.Join(repoRoot, "agentsdk"),
		filepath.Join(repoRoot, "goai"),
		filepath.Join(repoRoot, "sol"),
		filepath.Join(repoRoot, "telescope"))
	if err := os.WriteFile(filepath.Join(dir, "go.work"), []byte(goWork), 0o644); err != nil {
		t.Fatal(err)
	}

	// --- Step 1: Generate templ + Build ---
	templGen := exec.Command("templ", "generate")
	templGen.Dir = dir
	if out, err := templGen.CombinedOutput(); err != nil {
		t.Fatalf("templ generate failed:\n%s", out)
	}

	binPath := filepath.Join(dir, "agent")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = dir
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
