package builder

import (
	"fmt"
	"os"
	"path/filepath"
)

// buildGoVersion is the Go toolchain version baked into the agent-builder
// image. Mirrored in scaffold's go.mod template via ScaffoldData.GoVersion
// at call sites — bump both together.
const buildGoVersion = "1.26"

// buildGoWorkContent is the go.work file airlock injects into every
// codegen workspace and every docker build context. It overrides the
// agent's go.mod replace directives (which we keep absent from the
// committed go.mod so user clones compile against public modules) and
// redirects agentsdk/goai/sol/goose/templ to the airlock-bundled libs
// at /libs/. The file is gitignored at the scaffold level — committed
// copies are silently overwritten by writeBuildGoWork on every build.
const buildGoWorkContent = `go ` + buildGoVersion + `

use ./

replace (
	github.com/airlockrun/agentsdk => /libs/agentsdk
	github.com/airlockrun/goai => /libs/goai
	github.com/airlockrun/sol => /libs/sol
	github.com/pressly/goose/v3 => /libs/goose
	github.com/a-h/templ => /libs/templ
)
`

// writeBuildGoWork writes go.work into dir, overwriting any existing
// file (including one a user pushed in their repo — Principle 1: airlock
// silently overwrites managed files at build time).
func writeBuildGoWork(dir string) error {
	if err := os.WriteFile(filepath.Join(dir, "go.work"), []byte(buildGoWorkContent), 0o644); err != nil {
		return fmt.Errorf("write go.work: %w", err)
	}
	return nil
}
