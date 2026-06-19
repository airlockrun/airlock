package builder

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/goai/tool"
	sol "github.com/airlockrun/sol"
	"github.com/google/uuid"
)

// runCodegen is Execute's Phase C: optional Sol invocation. Returns
// (commitHash, exitStatus, exitMessage, error). commitHash is the new HEAD
// after merge; exitStatus is the agent's exit-tool status ("success" |
// "error" | "refused", empty if it never called exit) and exitMessage its
// summary/reason — both persisted on the build row and (on success) plumbed
// into the originating conversation by upper layers.
//
// When plan.Instruction is empty this is a no-op: returns ("", "", "", nil)
// and Execute falls back to current HEAD as the source ref.
func (b *BuildService) runCodegen(
	ctx context.Context,
	plan BuildPlan,
	agent dbq.Agent,
	build dbq.AgentBuild,
	agentID string,
	agentUUID uuid.UUID,
	testDBURL, testDBPSQL, testDBSchema string,
	goProxyDir string,
	logLine func(string),
	sink buildSink,
) (string, string, string, error) {
	if plan.Instruction == "" {
		return "", "", "", nil
	}

	repoPath := b.AgentRepoPath(agentID)
	branch := codegenBranchName(plan)

	if err := CreateBranch(repoPath, branch); err != nil {
		return "", "", "", fmt.Errorf("create %s branch: %w", branch, err)
	}

	workDir, err := b.makeCodegenTempDir("airlock-codegen-*")
	if err != nil {
		return "", "", "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	if err := CloneAgentRepo(repoPath, branch, workDir); err != nil {
		return "", "", "", fmt.Errorf("clone agent repo: %w", err)
	}
	// Lib resolution: the toolserver gets GOPROXY pointed at the dev lib
	// proxy (when goProxyDir is set) so codegen's go-tool calls resolve
	// agentsdk/goai/sol from live source. The committed go.mod stays clean
	// (published versions, no replaces) — see solRunOpts.GoProxyDir.

	// Auto-fix diagnostics file lands in the workspace before Sol runs.
	if plan.Diagnostics != nil {
		if err := writePlanDiagnostics(workDir, plan); err != nil {
			return "", "", "", fmt.Errorf("write diagnostics: %w", err)
		}
	}

	if ctx.Err() != nil {
		return "", "", "", ctx.Err()
	}

	localTools := tool.Set{}
	if plan.Kind == BuildKindBuild {
		// Only the fresh-build flow currently registers MCP-probe — it's
		// useful when the LLM is wiring up integrations for the first
		// time. Upgrade/rollback keep the existing toolset.
		localTools.Add(newMCPProbeTool())
	}

	solResult, err := b.runSolInProcess(ctx, solRunOpts{
		WorkDir:         workDir,
		AgentDir:        "/workspace",
		AgentID:         agent.ID,
		BuildID:         build.ID,
		BuildType:       string(plan.Kind),
		BuildProviderID: agent.BuildProviderID,
		BuildModel:      agent.BuildModel,
		Prompt:          codegenPrompt(plan, agent),
		LocalTools:      localTools,
		TestDBURL:       testDBURL,
		TestDBPSQL:      testDBPSQL,
		TestDBSchema:    testDBSchema,
		GoProxyDir:      goProxyDir,
		LogCallback:     logLine,
		Sink:            sink,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("sol run: %w", err)
	}

	// Exit-tool mapping. RunExited + ExitStatus=="success" → success
	// path. ExitStatus=="refused" → RefusedError, which Execute records
	// as a "refused" build (the request was out of scope, not a
	// failure). Any other exit status → plain error → failed build.
	// RunCompleted (no exit after nudges) → treat as failure (agent
	// forgot to call exit; we have no signal whether the work is good).
	// Anything else wraps the underlying error with %w so the outer
	// cancellation check still fires via errors.Is.
	if solResult.Status != sol.RunExited {
		if solResult.Status == sol.RunCompleted {
			logLine("[exit] agent did not call the exit tool after 2 reminders — treating as failure")
			return "", "", "", errors.New("sol codegen failed: agent did not call the exit tool")
		}
		if solResult.Error != nil {
			return "", "", "", fmt.Errorf("sol codegen failed: %w", solResult.Error)
		}
		return "", "", "", errors.New("sol codegen failed")
	}
	if solResult.ExitStatus != exitStatusSuccess {
		if solResult.ExitStatus == exitStatusRefused {
			logLine(fmt.Sprintf("[exit] agent declined the request as out of scope: %s", solResult.ExitMessage))
			return "", exitStatusRefused, solResult.ExitMessage, &RefusedError{Message: solResult.ExitMessage}
		}
		logLine(fmt.Sprintf("[exit] agent reported error: %s", solResult.ExitMessage))
		// Return the exit message verbatim — the conversation notifier
		// surfaces err.Error() as the "agent reports it failed because…"
		// line for the user.
		return "", exitStatusError, solResult.ExitMessage, errors.New(solResult.ExitMessage)
	}
	logLine(fmt.Sprintf("[exit] success: %s", solResult.ExitMessage))

	commitMsg := fmt.Sprintf("%s agent %s", plan.Kind, agentID)
	if plan.Reason != "" {
		commitMsg = fmt.Sprintf("%s agent %s: %s", plan.Kind, agentID, plan.Reason)
	}
	hash, err := CommitAndPush(workDir, commitMsg)
	if err != nil {
		return "", "", "", fmt.Errorf("commit codegen: %w", err)
	}
	if err := MergeBranch(repoPath, branch); err != nil {
		return "", "", "", fmt.Errorf("merge codegen: %w", err)
	}
	return hash, exitStatusSuccess, solResult.ExitMessage, nil
}

// codegenBranchName picks a working-branch name per kind so concurrent
// pipelines for the same agent don't collide on the same ref. Upgrade
// and rollback include the RunID so each invocation is independent;
// initial build uses a fixed name (only one initial build per agent).
func codegenBranchName(plan BuildPlan) string {
	switch plan.Kind {
	case BuildKindBuild:
		return "build/codegen"
	case BuildKindUpgrade:
		return UpgradeBranchName(plan.RunID)
	case BuildKindRollback:
		return "rollback/" + plan.RunID
	}
	return "codegen"
}

// codegenPrompt selects the right user-turn template based on plan kind
// + presence of diagnostics. The build template frames the work as
// from-scratch; upgrade frames it as an incremental change against a
// working tree; auto-fix layers in DIAGNOSTICS.md context.
func codegenPrompt(plan BuildPlan, agent dbq.Agent) string {
	switch plan.Kind {
	case BuildKindBuild:
		return buildCodegenPrompt(agent, plan.Instruction)
	default:
		input := UpgradeInput{
			Description: plan.Instruction,
			RunID:       plan.RunID,
		}
		return buildUpgradePrompt(agent, input, plan.Diagnostics != nil)
	}
}

// writePlanDiagnostics writes the same DIAGNOSTICS.md the legacy
// upgrade flow wrote, just sourced from the plan's AutoFixContext
// instead of the UpgradeInput struct directly.
func writePlanDiagnostics(workDir string, plan BuildPlan) error {
	d := plan.Diagnostics
	input := UpgradeInput{
		RunID:        plan.RunID,
		ErrorMessage: d.ErrorMessage,
		PanicTrace:   d.PanicTrace,
		InputPayload: d.InputPayload,
		Actions:      d.Actions,
		Messages:     d.Messages,
		Logs:         d.Logs,
	}
	_, err := writeUpgradeDiagnostics(workDir, input)
	return err
}
