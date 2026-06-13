package sysagent

import (
	"context"

	"github.com/airlockrun/goai/tool"
	"github.com/airlockrun/sol/bus"
)

// gatedExecutor wraps a base tool.Executor and gates destructive tool
// calls through Sol's PermissionManager. The flow:
//
//  1. Tool fires; if isDestructive(name) → pm.Ask(...).
//  2. Ask checks PermissionManager rules for {permission=<toolName>,
//     pattern=*}. If a matching "allow" rule exists (set by the
//     resume path after the user approved), proceed.
//  3. Otherwise Ask returns *bus.ErrPermissionNeeded. The error
//     propagates through Sol's runner, which suspends the run with
//     RunResult.Status = RunSuspended + a SuspensionContext.
//  4. The chat loop persists the SuspensionContext to
//     system_conversations.checkpoint, emits a confirmation_required
//     event, and returns. UI shows Approve/Deny.
//  5. On Approve, the resume path adds an "allow" rule, executes the
//     gated tools with the permissive PM (sol's pending-tool-call
//     resolution), persists results, then Runner.Continue.
//
// Non-destructive tools delegate straight to the base.
type gatedExecutor struct {
	base          tool.Executor
	isDestructive func(toolName string) bool
}

// newGatedExecutor wraps base with the destructive-tool gate.
// isDestructive defaults to the package's hardcoded set (see tools.go).
func newGatedExecutor(base tool.Executor) *gatedExecutor {
	return &gatedExecutor{base: base, isDestructive: isDestructiveTool}
}

func (e *gatedExecutor) Execute(ctx context.Context, req tool.Request) (tool.Response, error) {
	if e.isDestructive(req.ToolName) {
		pm := bus.PermissionManagerFromContext(ctx)
		err := pm.Ask(ctx, bus.PermissionRequest{
			Permission: req.ToolName,
			// "*" is a match-anything placeholder — sysagent gates on
			// tool identity, not on a per-call pattern. PermissionRule
			// {permission=<toolName>, pattern=*, action=allow} unlocks
			// it for the rest of the run on resume.
			Patterns:   []string{"*"},
			ToolCallID: req.ToolCallID,
			Metadata:   map[string]any{"args": string(req.Input)},
		})
		if err != nil {
			// PermissionDeniedError → record as a tool-level denial so
			// the LLM apologises rather than the whole run failing.
			// ErrPermissionNeeded → propagate so the runner suspends.
			if _, denied := err.(*bus.PermissionDeniedError); denied {
				return tool.Response{
					Denied:       true,
					DeniedReason: err.Error(),
				}, nil
			}
			return tool.Response{}, err
		}
	}
	return e.base.Execute(ctx, req)
}

func (e *gatedExecutor) Tools() []tool.Info {
	return e.base.Tools()
}
