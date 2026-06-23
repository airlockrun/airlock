package builder

import (
	"slices"
	"testing"

	"github.com/airlockrun/airlock/config"
)

func TestBuildxBuildArgs(t *testing.T) {
	const tag = "agent123:abcdef012345"
	const inst = "inst"
	df := "/tmp/df/Dockerfile"
	ctxDir := "/repos/agent123"

	// Local (no registry): --load, no goproxy. Carries the instance label.
	got := buildxBuildArgs(tag, df, ctxDir, "", false, inst)
	want := []string{
		"buildx", "build", "--builder", buildxBuilderName(inst), "--progress=plain",
		"-t", tag, "--label", config.LabelInstance + "=" + inst, "--load", "-f", df, ctxDir,
	}
	if !slices.Equal(got, want) {
		t.Errorf("local args:\n got %v\nwant %v", got, want)
	}

	// Registry: --push instead of --load.
	push := buildxBuildArgs(tag, df, ctxDir, "", true, inst)
	if slices.Contains(push, "--load") || !slices.Contains(push, "--push") {
		t.Errorf("registry args should use --push not --load: %v", push)
	}

	// Dev goproxy context wired in.
	dev := buildxBuildArgs(tag, df, ctxDir, "/tmp/goproxy", false, inst)
	if i := slices.Index(dev, "--build-context"); i < 0 || dev[i+1] != "goproxy=/tmp/goproxy" {
		t.Errorf("goproxy build-context not wired: %v", dev)
	}

	// Context dir is always last.
	if got[len(got)-1] != ctxDir {
		t.Errorf("context dir not last: %v", got)
	}
}
