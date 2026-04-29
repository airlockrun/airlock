package builder

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// bumpAgentSDKRequire rewrites the agent's go.mod `require` line for
// github.com/airlockrun/agentsdk to the given version. The version is
// informational only — replace directives in the agent's go.mod always
// resolve agentsdk/goai/sol from /libs/ — but keeping the require line in
// sync with the agent-builder's baked SDK gives editor tooling (gopls,
// jump-to-definition, version display) something accurate to show.
//
// Idempotent: a no-op if the require line is already at the target version.
func bumpAgentSDKRequire(ctx context.Context, agentDir, version string) error {
	require := "github.com/airlockrun/agentsdk@v" + strings.TrimPrefix(version, "v")
	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-require="+require)
	cmd.Dir = agentDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go mod edit -require=%s: %s: %w", require, strings.TrimSpace(string(out)), err)
	}
	return nil
}
