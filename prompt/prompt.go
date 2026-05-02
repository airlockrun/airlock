// Package prompt provides template rendering for agent system prompts.
package prompt

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"text/template"

	"github.com/airlockrun/agentsdk/tsrender"
)

//go:embed agent.tmpl
var agentPromptTmpl string

var agentTmpl = template.Must(template.New("agent").Funcs(template.FuncMap{
	"renderTools":        renderToolsFunc,
	"renderMCPNamespace": renderMCPNamespaceFunc,
}).Parse(agentPromptTmpl))

// AgentData is the template data for rendering the execution agent system prompt.
type AgentData struct {
	AgentDashboardURL string // e.g., "https://airlock.example.com/agents/{id}"
	AgentRouteURL     string // e.g., "https://myagent.dev.airlock.run" (empty if no agent domain)
	Tools             []ToolInfo
	Connections       []ConnInfo
	Topics            []TopicInfo
	Webhooks          []WebhookInfo
	Crons             []CronInfo
	Routes            []RouteInfo
	MCPServers        []MCPServerStatus
}

// ToolInfo carries the hydrated tool record for prompt rendering.
// InputSchema and OutputSchema are JSON-encoded JSON Schemas.
// LLMHint is optional model-only guidance that pairs with Description
// (which surfaces in the dashboard's Tools tab); see agentsdk.Tool.LLMHint.
type ToolInfo struct {
	Name         string
	Description  string
	LLMHint      string
	InputSchema  json.RawMessage
	OutputSchema json.RawMessage
}

// renderToolsFunc is the template helper that turns a []ToolInfo into the
// TypeScript .d.ts block the LLM reads. Delegates to agentsdk so the same
// renderer is used by both sides.
func renderToolsFunc(tools []ToolInfo) string {
	items := make([]tsrender.ToolRender, len(tools))
	for i, t := range tools {
		items[i] = tsrender.ToolRender{
			Name:         t.Name,
			Description:  t.Description,
			LLMHint:      t.LLMHint,
			InputSchema:  t.InputSchema,
			OutputSchema: t.OutputSchema,
		}
	}
	return tsrender.RenderToolDecls(items)
}

type ConnInfo struct {
	Slug        string
	Name        string
	Description string
	LLMHint     string
	BaseURL     string
}

type TopicInfo struct {
	Slug        string
	Description string
	LLMHint     string
}

type WebhookInfo struct {
	Path        string
	Description string
}

type CronInfo struct {
	Name        string
	Schedule    string
	Description string
}

type RouteInfo struct {
	Method      string
	Path        string
	Access      string
	Description string
}

type MCPServerStatus struct {
	Slug   string
	Name   string
	Status string // e.g. "connected, 5 tools" or "requires authentication"
	// Tools is empty when the server isn't authorized or discovery hasn't run.
	// When populated, the template renders a typed `declare const mcp_{slug}: {...}`
	// block alongside the status line.
	Tools []ToolInfo
}

// renderMCPNamespaceFunc adapts a single MCPServerStatus into the typed
// `declare const mcp_{slug}: {...}` block that the LLM consumes. Returns
// the empty string for unauthorized / undiscovered servers; the template
// then falls back to just the status line.
func renderMCPNamespaceFunc(server MCPServerStatus) string {
	if len(server.Tools) == 0 {
		return ""
	}
	tools := make([]tsrender.MCPToolRender, len(server.Tools))
	for i, t := range server.Tools {
		tools[i] = tsrender.MCPToolRender{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		}
	}
	return tsrender.RenderMCPNamespace(server.Slug, tools)
}

// RenderAgentPrompt renders the execution agent system prompt with the given data.
func RenderAgentPrompt(data AgentData) (string, error) {
	var buf bytes.Buffer
	if err := agentTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
