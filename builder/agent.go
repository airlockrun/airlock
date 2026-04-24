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
		MaxSteps:     50,
	}
}
