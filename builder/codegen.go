package builder

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

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

	if err := MaterializeBranch(repoPath, branch, workDir); err != nil {
		return "", "", "", fmt.Errorf("materialize agent repo: %w", err)
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

	commitMsg := codegenCommitMessage(plan, agentID, solResult.ExitMessage)

	// Mirror the agent's edits into the per-agent repo (excluding the
	// airlock-injected DIAGNOSTICS.md) and commit them host-side. The agent
	// never had a .git to commit into, so this is airlock's sole, deterministic
	// commit of the work.
	if err := SyncWorkdirToRepo(workDir, repoPath, []string{"DIAGNOSTICS.md"}); err != nil {
		return "", "", "", fmt.Errorf("sync codegen workspace: %w", err)
	}
	hash, committed, err := CommitWorktree(repoPath, commitMsg)
	if err != nil {
		return "", "", "", fmt.Errorf("commit codegen: %w", err)
	}
	if !committed {
		// Agent exited success but changed nothing. Leave HEAD untouched and
		// let Execute fall through to current HEAD as the source ref.
		return "", exitStatusSuccess, solResult.ExitMessage, nil
	}
	if err := MergeBranch(repoPath, branch); err != nil {
		return "", "", "", fmt.Errorf("merge codegen: %w", err)
	}
	return hash, exitStatusSuccess, solResult.ExitMessage, nil
}

// codegenCommitMessage builds the git commit message for a successful
// codegen result: a subject line from the user's instruction, the agent's
// own exit-tool summary as the body, and Reason/Run trailers for
// provenance. Falls back to the exit summary, then a generic
// "<kind> agent <id>", when no instruction is present (defensive — codegen
// only runs with a non-empty instruction).
func codegenCommitMessage(plan BuildPlan, agentID, exitSummary string) string {
	// Codegen models often write the exit summary as markdown; strip it so the
	// committed message reads as plain prose.
	exitSummary = stripMarkdown(exitSummary)
	subject := firstLine(plan.Instruction)
	if subject == "" {
		subject = firstLine(exitSummary)
	}
	if subject == "" {
		subject = fmt.Sprintf("%s agent %s", plan.Kind, agentID)
	}
	subject = truncateSubject(subject, 72)

	var b strings.Builder
	b.WriteString(subject)
	if body := strings.TrimSpace(exitSummary); body != "" && body != subject {
		b.WriteString("\n\n")
		b.WriteString(body)
	}
	b.WriteString("\n")
	if plan.Reason != "" {
		fmt.Fprintf(&b, "\nReason: %s", plan.Reason)
	}
	if plan.RunID != "" {
		fmt.Fprintf(&b, "\nRun: %s", plan.RunID)
	}
	return b.String()
}

// Markdown-stripping patterns, compiled once. Applied to the agent's exit
// summary before it becomes a git commit body.
var (
	mdFenceLine  = regexp.MustCompile("(?m)^[ \t]*```.*\n?")     // ``` fence lines
	mdHeading    = regexp.MustCompile(`(?m)^[ \t]*#{1,6}[ \t]+`) // # heading markers
	mdBlockquote = regexp.MustCompile(`(?m)^[ \t]*>[ \t]?`)      // > blockquote markers
	mdBullet     = regexp.MustCompile(`(?m)^([ \t]*)[*+][ \t]+`) // *,+ bullets -> "- "
	mdImage      = regexp.MustCompile(`!\[[^\]]*\]\([^)]*\)`)    // ![alt](url) -> drop
	mdLink       = regexp.MustCompile(`\[([^\]]+)\]\([^)]*\)`)   // [text](url) -> text
	mdInlineCode = regexp.MustCompile("`+([^`\n]*?)`+")          // `code` -> code
	mdItalicStar = regexp.MustCompile(`\*([^*\n]+?)\*`)          // *italic* -> italic
	mdBlankRuns  = regexp.MustCompile(`\n{3,}`)                  // collapse blank-line runs
)

// stripMarkdown reduces the common markdown an LLM emits to plain text: it
// drops code-fence lines, heading/blockquote markers and image syntax,
// normalizes bullets to "- ", rewrites [text](url) to text, and removes
// inline-code backticks and ** / * emphasis. Underscores are left untouched so
// snake_case identifiers in the summary survive. It's a pragmatic cleanup for a
// commit body, not a full CommonMark parser.
func stripMarkdown(s string) string {
	s = mdImage.ReplaceAllString(s, "")
	s = mdFenceLine.ReplaceAllString(s, "")
	s = mdHeading.ReplaceAllString(s, "")
	s = mdBlockquote.ReplaceAllString(s, "")
	s = mdBullet.ReplaceAllString(s, "$1- ")
	s = mdLink.ReplaceAllString(s, "$1")
	s = mdInlineCode.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, "**", "")
	s = mdItalicStar.ReplaceAllString(s, "$1")
	s = mdBlankRuns.ReplaceAllString(s, "\n\n")
	return s
}

// firstLine returns the first non-empty line of s, trimmed.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// truncateSubject caps a commit subject at max runes, appending an ellipsis
// when it had to cut.
func truncateSubject(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return strings.TrimSpace(string(r[:max])) + "…"
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
		BuildError:   d.BuildError,
		BuildLog:     d.BuildLog,
	}
	_, err := writeUpgradeDiagnostics(workDir, input)
	return err
}
