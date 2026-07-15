package builder

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"
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

var agentModuleTools = []string{
	"github.com/a-h/templ/cmd/templ",
	"github.com/airlockrun/agentsdk/cmd/air",
}

// reconcileAgentGoMod ensures the agent's go.mod can build against Airlock's
// SDK series and exposes the module-local tools required by the build chain.
// Production preserves a same-series requirement that is at least as new as
// Airlock's pin; older or incompatible requirements are rewritten. Development
// always uses the exact content-addressed version served by its module proxy.
//
// Implemented with a narrow requirement edit plus x/mod parsing rather than
// shelling out to `go mod edit`: the Airlock container that runs the upgrade
// flow ships only the Airlock binary, not the Go toolchain.
//
// Idempotent when the requirement and tool directives are already canonical.
func reconcileAgentGoMod(ctx context.Context, agentDir, version string) error {
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
	updated := body
	if strings.Contains(v, "-dev") || !compatibleAgentSDKRequire(current, v) {
		updated = agentSDKRequireLine.ReplaceAll(body, []byte("${1}"+v))
	}

	mf, err := modfile.Parse(gomod, updated, nil)
	if err != nil {
		return fmt.Errorf("parse %s: %w", gomod, err)
	}
	present := make(map[string]bool, len(mf.Tool))
	for _, tool := range mf.Tool {
		present[tool.Path] = true
	}
	toolsChanged := false
	for _, tool := range agentModuleTools {
		if present[tool] {
			continue
		}
		if err := mf.AddTool(tool); err != nil {
			return fmt.Errorf("add tool %s: %w", tool, err)
		}
		toolsChanged = true
	}
	if toolsChanged {
		updated, err = mf.Format()
		if err != nil {
			return fmt.Errorf("format %s: %w", gomod, err)
		}
	}
	if string(updated) == string(body) {
		return nil
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
