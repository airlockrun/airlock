package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/goai"
	"github.com/airlockrun/sol"
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

	for _, m := range libProxyMods() {
		base := filepath.Join(proxy, filepath.FromSlash(m.path), "@v")
		for _, f := range []string{"list", m.version + ".info", m.version + ".mod", m.version + ".zip"} {
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

	// The served agentsdk .mod must carry the inter-lib requires REWRITTEN
	// to the const versions (not the lib repo's lagging published pins), so
	// the module graph selects the proxy's local goai/sol.
	agentsdkMod := filepath.Join(proxy, "github.com/airlockrun/agentsdk", "@v", "v"+agentsdk.Version+".mod")
	body, err := os.ReadFile(agentsdkMod)
	if err != nil {
		t.Fatalf("read served agentsdk .mod: %v", err)
	}
	for _, want := range []string{
		"github.com/airlockrun/goai v" + goai.Version,
		"github.com/airlockrun/sol v" + sol.Version,
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
	// A module zip including .git would balloon well past the source size;
	// assert the agentsdk zip is comfortably small (source is well under
	// the module-zip 500MB cap and .git would dominate if included).
	zip := filepath.Join(proxy, "github.com/airlockrun/agentsdk", "@v", "v"+agentsdk.Version+".zip")
	fi, err := os.Stat(zip)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 50<<20 { // 50 MiB — generous headroom for source-only
		t.Errorf("agentsdk zip is %d bytes — .git likely included", fi.Size())
	}
}

func TestBustLibCacheShell(t *testing.T) {
	got := bustLibCacheShell("/tmp/go-mod")
	for _, want := range []string{
		"chmod -R u+w",
		"/tmp/go-mod/cache/download/github.com/airlockrun/agentsdk",
		"/tmp/go-mod/github.com/airlockrun/sol@*",
		"|| true",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("bust shell missing %q:\n%s", want, got)
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
