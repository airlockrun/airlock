package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

// hqRoot resolves the monorepo root (parent of airlock/) so the generator
// can read the real lib source trees. Skips the test when not running
// inside the hq layout.
func hqRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd() // .../airlock/builder
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	for _, sub := range []string{"agentsdk", "goai", "sol"} {
		if _, err := os.Stat(filepath.Join(root, sub, "go.mod")); err != nil {
			t.Skipf("not in hq layout (missing %s/go.mod): %v", sub, err)
		}
	}
	return root
}

func TestGenerateLibProxy(t *testing.T) {
	root := hqRoot(t)
	proxy := t.TempDir()
	if err := generateLibProxy(proxy, root); err != nil {
		t.Fatalf("generateLibProxy: %v", err)
	}

	versions, err := computeDevVersions(root)
	if err != nil {
		t.Fatalf("computeDevVersions: %v", err)
	}

	for _, m := range proxiedLibs() {
		ver := versions[m.path]
		base := filepath.Join(proxy, filepath.FromSlash(m.path), "@v")
		for _, f := range []string{"list", ver + ".info", ver + ".mod", ver + ".zip"} {
			fi, err := os.Stat(filepath.Join(base, f))
			if err != nil {
				t.Errorf("%s/%s: %v", m.path, f, err)
				continue
			}
			if strings.HasSuffix(f, ".zip") && fi.Size() == 0 {
				t.Errorf("%s/%s is empty", m.path, f)
			}
		}
	}

	// The served agentsdk .mod must carry the inter-lib requires REWRITTEN to
	// the proxy's content-addressed dev versions (not the lib repo's lagging
	// published pins), so the module graph selects the proxy's local goai/sol.
	agentsdkMod := filepath.Join(proxy, "github.com/airlockrun/agentsdk", "@v", versions["github.com/airlockrun/agentsdk"]+".mod")
	body, err := os.ReadFile(agentsdkMod)
	if err != nil {
		t.Fatalf("read served agentsdk .mod: %v", err)
	}
	for _, want := range []string{
		"github.com/airlockrun/goai " + versions["github.com/airlockrun/goai"],
		"github.com/airlockrun/sol " + versions["github.com/airlockrun/sol"],
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("served agentsdk .mod missing rewritten require %q:\n%s", want, body)
		}
	}
}

func TestGenerateLibProxy_ZipExcludesGit(t *testing.T) {
	root := hqRoot(t)
	// Only meaningful if a lib actually has a .git dir (it does in a clone).
	if _, err := os.Stat(filepath.Join(root, "agentsdk", ".git")); err != nil {
		t.Skip("agentsdk has no .git to exclude")
	}
	proxy := t.TempDir()
	if err := generateLibProxy(proxy, root); err != nil {
		t.Fatalf("generateLibProxy: %v", err)
	}
	versions, err := computeDevVersions(root)
	if err != nil {
		t.Fatalf("computeDevVersions: %v", err)
	}
	// A module zip including .git would balloon well past the source size;
	// assert the agentsdk zip is comfortably small (source is well under
	// the module-zip 500MB cap and .git would dominate if included).
	zip := filepath.Join(proxy, "github.com/airlockrun/agentsdk", "@v", versions["github.com/airlockrun/agentsdk"]+".zip")
	fi, err := os.Stat(zip)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 50<<20 { // 50 MiB — generous headroom for source-only
		t.Errorf("agentsdk zip is %d bytes — .git likely included", fi.Size())
	}
}

func TestComputeDevVersions(t *testing.T) {
	root := hqRoot(t)
	v1, err := computeDevVersions(root)
	if err != nil {
		t.Fatalf("computeDevVersions: %v", err)
	}
	v2, err := computeDevVersions(root)
	if err != nil {
		t.Fatalf("computeDevVersions (second): %v", err)
	}
	for _, m := range proxiedLibs() {
		ver := v1[m.path]
		if ver == "" {
			t.Errorf("%s: no version computed", m.path)
			continue
		}
		// Deterministic: identical source → identical version, so concurrent
		// builds agree and a cache entry is immutable per version.
		if ver != v2[m.path] {
			t.Errorf("%s: non-deterministic version %q vs %q", m.path, ver, v2[m.path])
		}
		// Valid semver carrying a -dev<hash> segment. The "-dev"+hex segment is
		// always alphanumeric, so the version stays valid even when the const
		// already has a prerelease (e.g. v0.3.0-rc.1-dev<hash>).
		if !semver.IsValid(ver) {
			t.Errorf("%s: invalid semver %q", m.path, ver)
		}
		if !strings.Contains(ver, "-dev") {
			t.Errorf("%s: expected a -dev segment, got %q", m.path, ver)
		}
	}
}

func TestDevGoProxy(t *testing.T) {
	got := devGoProxy("/var/lib/airlock/goproxy")
	want := "file:///var/lib/airlock/goproxy,https://proxy.golang.org"
	if got != want {
		t.Errorf("devGoProxy = %q, want %q", got, want)
	}
}
