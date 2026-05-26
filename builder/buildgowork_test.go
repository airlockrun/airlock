package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteBuildGoWork(t *testing.T) {
	dir := t.TempDir()

	if err := writeBuildGoWork(dir); err != nil {
		t.Fatalf("writeBuildGoWork: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "go.work"))
	if err != nil {
		t.Fatalf("read go.work: %v", err)
	}
	s := string(got)

	if !strings.Contains(s, "go "+buildGoVersion) {
		t.Errorf("go.work missing go directive %q; got:\n%s", buildGoVersion, s)
	}
	if !strings.Contains(s, "use ./") {
		t.Errorf("go.work missing `use ./` directive; got:\n%s", s)
	}
	for _, want := range []string{
		"github.com/airlockrun/agentsdk => /libs/agentsdk",
		"github.com/airlockrun/goai => /libs/goai",
		"github.com/airlockrun/sol => /libs/sol",
		"github.com/pressly/goose/v3 => /libs/goose",
		"github.com/a-h/templ => /libs/templ",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("go.work missing %q", want)
		}
	}
}

func TestWriteBuildGoWork_Overwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.work")

	if err := os.WriteFile(path, []byte("stale user content"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeBuildGoWork(dir); err != nil {
		t.Fatalf("writeBuildGoWork: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(got), "stale user content") {
		t.Error("writeBuildGoWork did not overwrite existing file (Principle 1: managed files are silently overwritten)")
	}
}
