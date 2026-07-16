package builder

import (
	"context"

	"github.com/airlockrun/goai/tool"
)

// compositeExecutor routes tool calls between a remote executor (toolserver)
// and a local executor (in-process tools like set_agent_description).
type compositeExecutor struct {
	remote tool.Executor
	local  *tool.LocalExecutor
}

// Execute routes to local if the tool exists locally, otherwise to remote.
func (c *compositeExecutor) Execute(ctx context.Context, req tool.Request) (tool.Response, error) {
	for _, info := range c.local.Tools() {
		if info.Name == req.ToolName {
			return c.local.Execute(ctx, req)
		}
	}
	return c.remote.Execute(ctx, req)
}

// Tools returns the combined tool list from both executors.
func (c *compositeExecutor) Tools() []tool.Info {
	return append(c.remote.Tools(), c.local.Tools()...)
}
