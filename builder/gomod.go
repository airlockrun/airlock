package builder

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
var agentSDKRequireLine = regexp.MustCompile(`(?m)^([\t ]*(?:require[\t ]+)?github\.com/airlockrun/agentsdk[\t ]+)v[^\s]+`)

// bumpAgentSDKRequire rewrites the agent's go.mod `require` line for
// github.com/airlockrun/agentsdk to the given version. The version is
// informational only — replace directives in the agent's go.mod always
// resolve agentsdk/goai/sol from /libs/ — but keeping the require line in
// sync with the agent-builder's baked SDK gives editor tooling (gopls,
// jump-to-definition, version display) something accurate to show.
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
	if !agentSDKRequireLine.Match(body) {
		return fmt.Errorf("%s: no require directive for github.com/airlockrun/agentsdk", gomod)
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
