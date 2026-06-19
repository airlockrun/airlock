package builder

import (
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

// BuildKind discriminates the three flows that share the Execute pipeline.
type BuildKind string

const (
	BuildKindBuild    BuildKind = "build"
	BuildKindUpgrade  BuildKind = "upgrade"
	BuildKindRollback BuildKind = "rollback"
)

// BuildPlan is the single input to Execute. Each external entry point
// (Build, RunUpgrade, Rollback) constructs one of these and hands it off;
// Execute is the only function that contains the full pipeline.
//
// Fields are interpreted as follows:
//
//   - Agent / Kind / RunID / Reason / ConversationID: always required.
//   - Scaffold: required iff Kind=build (the repo doesn't exist yet).
//   - StartCommit + PreserveBranch: rollback only — Phase B saves
//     current HEAD under PreserveBranch then resets main to StartCommit.
//   - Instruction: empty = no Sol invocation (bare rebuild / pure
//     rollback); non-empty = Sol runs with this as the user-turn prompt
//     and the string is also persisted on agent_builds.instructions.
//   - RollbackTargetID: rollback only — points the new agent_builds row
//     at the build we're rolling back to (UI uses it for the label).
//   - Diagnostics: upgrade auto_fix only — writes DIAGNOSTICS.md into
//     the codegen workspace before Sol sees it.
type BuildPlan struct {
	Agent dbq.Agent
	Kind  BuildKind

	StartCommit    string
	PreserveBranch string

	Instruction string

	RollbackTargetID pgtype.UUID

	Scaffold *ScaffoldInputs

	RunID          string
	ConversationID string
	Reason         string

	Diagnostics *AutoFixContext
}

// ScaffoldInputs carries the per-build creation parameters that
// only the initial-build flow uses. Lives on BuildPlan as an optional
// pointer so Kind=upgrade / Kind=rollback don't have to pass nil
// fields, and so Execute's "is this a fresh build?" check is the
// presence of the pointer instead of a magic string compare.
type ScaffoldInputs struct {
	Name            string
	Slug            string
	BuildProviderID pgtype.UUID
	BuildModel      string
}

// AutoFixContext is the failure trail that gets written into DIAGNOSTICS.md
// before Sol sees the workspace, so the builder agent can diagnose the
// failure. Two independent sources: a failed runtime run (ErrorMessage …
// Logs) and the agent's previous failed build (BuildError/BuildLog — the
// docker/migration breakage that the prior codegen committed to main but
// never got deployed). Mirrors the corresponding subset of UpgradeInput.
type AutoFixContext struct {
	ErrorMessage string
	PanicTrace   string
	InputPayload string
	Actions      string
	Messages     string
	Logs         string // captured log lines from the failed run

	BuildError string // error_message of the agent's most recent failed build
	BuildLog   string // tail of that build's docker log
}
