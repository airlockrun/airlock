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
func newExitTool(state *soltools.ExitState) tool.Tool {
	if state == nil {
		panic("builder: newExitTool called with nil ExitState")
	}
	return tool.New("exit").
		Description(`Call this tool exactly once, as your final action, when you finish your task or determine you cannot.

Set status="success" with a one-paragraph summary when the task is complete and the binary builds.
Set status="error" only when you hit a blocker you cannot resolve from inside this build environment. An import cycle, compile error, or half-finished refactor is NOT a blocker - finish the work.
Set status="refused" with an explanation when the request is outside what an agentsdk agent can be (see the system prompt for what is in scope).

After calling this tool, the run ends immediately. Do NOT output additional text or call any other tool after exit.`).
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
			state.Set(p.Status, p.Message)
			return tool.Result{
				Output: "Run terminated. The runner will return RunExited.",
				Title:  "exit:" + p.Status,
			}, nil
		}).
		Build()
}
