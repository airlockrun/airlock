package builder

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/airlockrun/goai/tool"
	soltools "github.com/airlockrun/sol/tools"
)

// Agent-builder exit-tool status vocabulary. Sol's generic exit tool
// (sol/tools) only knows "success" and "error"; codegen runs add
// "refused" for requests that fall outside what an agentsdk agent can
// be. Sol stays domain-agnostic — we register our own exit tool here
// and drive sol's runner termination through the shared ExitState.
const (
	exitStatusSuccess = "success"
	exitStatusError   = "error"
	exitStatusRefused = "refused"
)

// errorPushback is the tool result returned to the model the first time
// it tries to exit with status="error". The runner is NOT terminated
// (we don't call ExitState.Set) so the model gets another turn to look
// at what it actually wants to do next. The second error call goes
// through normally.
//
// Why: codegen models tend to reach for exit-error mid-refactor —
// "intermediate state, can't finish" — when the real next move is just
// to keep editing. The bar for a true blocker is high (env, missing
// system capability, undocumented external API), and "I introduced an
// import cycle three turns ago" doesn't clear it.
const errorPushback = `Before exiting with error, double-check that you're actually blocked rather than mid-task.

A blocker means: the next action you would take is impossible from inside this build environment (a required package will not install, an external API the user asked you to call is down, the request needs a runtime capability airlock doesn't expose). It does NOT mean: an import cycle, a compile error, a missing type, a half-applied refactor, or any tree state you yourself produced — those are unfinished work and you must finish them.

Look at your last 3 tool calls. Were any edits, writes, or builds that succeeded (or even partially succeeded)? Then you are progressing — try the next concrete step instead of exiting.

This rejection consumes one warning. If you call exit with status="error" again, the run will terminate.`

// RefusedError signals that the agent-builder declined a request as
// outside agentsdk's scope (exit status "refused") rather than failing
// while attempting in-scope work. The pipeline maps it onto a
// non-alarming "declined" outcome — agent_builds.status="refused", the
// agent left untouched — instead of a build failure.
type RefusedError struct {
	Message string
}

func (e *RefusedError) Error() string { return e.Message }

type exitToolInput struct {
	Status  string `json:"status" description:"\"success\" (task complete), \"error\" (blocked by something you cannot resolve from this environment), or \"refused\" (request is outside agentsdk's scope)"`
	Message string `json:"message" description:"success: a brief summary of what was done; error: the blocker; refused: what fell outside scope and why"`
}

// newExitTool builds the agent-builder's exit tool. It mirrors sol's
// ExitTool but accepts the extra "refused" status, and writes the
// agent-reported outcome into the sol ExitState so sol's RunUntilExit
// termination still fires.
//
// The first attempt at status="error" is rejected with a pushback
// message — see errorPushback above. A second error call terminates
// normally. success and refused always terminate on the first call.
func newExitTool(state *soltools.ExitState) tool.Tool {
	if state == nil {
		panic("builder: newExitTool called with nil ExitState")
	}
	errorAttempts := 0
	return tool.New("exit").
		Description(`Call this tool exactly once, as your final action, when you finish your task or determine you cannot.

Set status="success" with a one-paragraph summary when the task is complete and the binary builds.
Set status="error" only when you hit a blocker you cannot resolve from inside this build environment. An import cycle, compile error, or half-finished refactor is NOT a blocker — finish the work. The first error call gets a warning and the run continues; the second terminates.
Set status="refused" with an explanation when the request is outside what an agentsdk agent can be (see the system prompt for what is in scope).

After a terminating call, the run ends immediately. Do NOT output additional text or call any other tool after a terminating exit.`).
		SchemaFromStruct(exitToolInput{}).
		Execute(func(ctx context.Context, input json.RawMessage, opts tool.CallOptions) (tool.Result, error) {
			var p exitToolInput
			if err := json.Unmarshal(input, &p); err != nil {
				return tool.Result{}, fmt.Errorf("exit: invalid input: %w", err)
			}
			switch p.Status {
			case exitStatusSuccess, exitStatusError, exitStatusRefused:
			default:
				return tool.Result{}, fmt.Errorf("exit: status must be %q, %q, or %q, got %q",
					exitStatusSuccess, exitStatusError, exitStatusRefused, p.Status)
			}
			if p.Status == exitStatusError {
				errorAttempts++
				if errorAttempts == 1 {
					return tool.Result{
						Output: errorPushback,
						Title:  "exit:error (challenged — run continues)",
					}, nil
				}
			}
			state.Set(p.Status, p.Message)
			return tool.Result{
				Output: "Run terminated. The runner will return RunExited.",
				Title:  "exit:" + p.Status,
			}, nil
		}).
		Build()
}
