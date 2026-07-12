package builder

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// agentSDKRequireLine matches the agent's require entry for agentsdk —
// either inside a `require ( ... )` block (tab/space-indented module
// path) or as a standalone `require github.com/airlockrun/agentsdk vX.Y.Z`
// line. Group 1 captures everything up to (and including the whitespace
// before) the version token so we can substitute the version cleanly.
//
// Replace directives (`github.com/airlockrun/agentsdk => /libs/agentsdk`)
// are not matched because the trailing `v[^\s]+` requires a version
// token, not `=>`.
var agentSDKRequireLine = regexp.MustCompile(`(?m)^([\t ]*(?:require[\t ]+)?github\.com/airlockrun/agentsdk[\t ]+)(v[^\s]+)`)

// bumpAgentSDKRequire ensures the agent's go.mod can build against Airlock's SDK
// series. Production preserves a same-series requirement that is at least as
// new as Airlock's pin; older or incompatible requirements are rewritten.
// Development always uses the exact content-addressed version served by its
// local module proxy.
//
// Implemented as a regex edit on go.mod rather than shelling out to
// `go mod edit`: the airlock container that runs the upgrade flow ships
// only the airlock binary, not the Go toolchain, so an exec of `go` would
// fail with `executable file not found in $PATH`. The require directive
// format is stable and trivial to rewrite directly.
//
// Idempotent: a no-op (no error) if the require line is already at the
// target version.
func bumpAgentSDKRequire(ctx context.Context, agentDir, version string) error {
	gomod := filepath.Join(agentDir, "go.mod")
	body, err := os.ReadFile(gomod)
	if err != nil {
		return fmt.Errorf("read %s: %w", gomod, err)
	}

	v := "v" + strings.TrimPrefix(version, "v")
	current, ok := agentSDKRequireVersion(body)
	if !ok {
		return fmt.Errorf("%s: no require directive for github.com/airlockrun/agentsdk", gomod)
	}
	if !strings.Contains(v, "-dev") && compatibleAgentSDKRequire(current, v) {
		return nil
	}
	updated := agentSDKRequireLine.ReplaceAll(body, []byte("${1}"+v))

	if string(updated) == string(body) {
		return nil // already at target version
	}
	if err := os.WriteFile(gomod, updated, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", gomod, err)
	}
	return nil
}

func agentSDKRequireVersion(gomod []byte) (string, bool) {
	match := agentSDKRequireLine.FindSubmatch(gomod)
	if match == nil {
		return "", false
	}
	return string(match[2]), true
}

func compatibleAgentSDKRequire(current, target string) bool {
	if !semver.IsValid(current) || !semver.IsValid(target) {
		return false
	}
	return semver.MajorMinor(current) == semver.MajorMinor(target) && semver.Compare(current, target) >= 0
}

func newerCompatibleAgentSDKRequire(current, target string) bool {
	if strings.Contains(target, "-dev") || !compatibleAgentSDKRequire(current, target) {
		return false
	}
	return semver.Compare(current, target) > 0
}
