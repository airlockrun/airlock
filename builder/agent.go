package builder

import (
	"bytes"
	_ "embed"
	"text/template"

	"github.com/airlockrun/goai/tool"
	"github.com/airlockrun/sol/agent"
)

//go:embed prompt/agentbuilder.tmpl
var agentBuilderPromptTmpl string

var builderTmpl = template.Must(template.New("builder").Parse(agentBuilderPromptTmpl))

const builderNudgeMessage = "You stopped without calling the `exit` tool. If the task is incomplete and you can still make progress, continue working now and use tools; do not call `exit`. Otherwise, call `exit` now with status `success` if the task is complete, `error` only if an external blocker makes completion impossible, or `refused` if the request is outside scope. Output nothing after calling `exit`."

// BuilderPromptData holds template data for the builder system prompt.
type BuilderPromptData struct {
	HasWebSearch bool
}

// newAgentBuilderAgent creates the agent-builder agent configuration.
func newAgentBuilderAgent(tools tool.Set, hasWebSearch bool) *agent.Agent {
	var buf bytes.Buffer
	builderTmpl.Execute(&buf, BuilderPromptData{HasWebSearch: hasWebSearch})

	return &agent.Agent{
		Name:         "agent-builder",
		SystemPrompt: buf.String(),
		Tools:        tools,
		MaxSteps:     100,
	}
}
