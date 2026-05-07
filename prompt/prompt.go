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
	AgentRouteURL     string // e.g., "https://myagent.dev.airlock.run"; required (always non-empty)
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
// Access is the registered access level ("admin"/"user"/"public") used by
// RenderAgentPrompt to filter the surface for non-admin callers — public
// runs must never see admin-only tools listed in the prompt, even though
// the VM also blocks the call at runtime.
type ToolInfo struct {
	Name         string
	Description  string
	LLMHint      string
	Access       string
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
	Access      string
}

type TopicInfo struct {
	Slug        string
	Description string
	LLMHint     string
	Access      string
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
	Access string // registered access level — filters this server out of non-matching prompt variants
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

// accessRank totally orders the three access levels so we can answer
// "is the caller's level high enough?" with a single integer compare.
// Mirrors agentsdk's unexported helper — duplicated here so the prompt
// package doesn't have to import agentsdk and risk a cycle.
func accessRank(s string) int {
	switch s {
	case "admin":
		return 3
	case "user":
		return 2
	case "public":
		return 1
	case "":
		// Empty defaults to user, matching agentsdk's accessSatisfies.
		return 2
	}
	return -1
}

// callerSatisfies reports whether a caller at level `caller` may see
// something registered at level `required`. Empty caller is treated as
// admin (the unfiltered base case used when callers don't pass a level).
func callerSatisfies(caller, required string) bool {
	if caller == "" {
		return true
	}
	return accessRank(caller) >= accessRank(required)
}

// RenderAgentPrompt renders the execution agent system prompt with the
// given data, filtering tools/connections/MCPs/topics/routes that the
// caller's access level cannot reach. callerAccess of "" means "render
// the unfiltered admin variant" — callers that want explicit gating must
// pass "admin", "user", or "public" by name. Filtering is necessary
// because the rendered prompt is cached and reused per-run; without it,
// public callers would learn about admin-tier surface in the system
// prompt even though the VM blocks the call at runtime.
func RenderAgentPrompt(data AgentData, callerAccess string) (string, error) {
	if callerAccess != "" {
		data = filterAgentData(data, callerAccess)
	}
	var buf bytes.Buffer
	if err := agentTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// filterAgentData returns a shallow copy of data with each access-tagged
// list narrowed to entries the caller can reach. Webhooks and crons are
// not access-tagged (they're triggers, not LLM-callable surface) so they
// pass through unchanged.
func filterAgentData(data AgentData, caller string) AgentData {
	out := data
	out.Tools = filterTools(data.Tools, caller)
	out.Connections = filterConns(data.Connections, caller)
	out.Topics = filterTopics(data.Topics, caller)
	out.Routes = filterRoutes(data.Routes, caller)
	out.MCPServers = filterMCPs(data.MCPServers, caller)
	return out
}

func filterTools(in []ToolInfo, caller string) []ToolInfo {
	if len(in) == 0 {
		return in
	}
	out := make([]ToolInfo, 0, len(in))
	for _, t := range in {
		if callerSatisfies(caller, t.Access) {
			out = append(out, t)
		}
	}
	return out
}

func filterConns(in []ConnInfo, caller string) []ConnInfo {
	if len(in) == 0 {
		return in
	}
	out := make([]ConnInfo, 0, len(in))
	for _, c := range in {
		if callerSatisfies(caller, c.Access) {
			out = append(out, c)
		}
	}
	return out
}

func filterTopics(in []TopicInfo, caller string) []TopicInfo {
	if len(in) == 0 {
		return in
	}
	out := make([]TopicInfo, 0, len(in))
	for _, t := range in {
		if callerSatisfies(caller, t.Access) {
			out = append(out, t)
		}
	}
	return out
}

func filterRoutes(in []RouteInfo, caller string) []RouteInfo {
	if len(in) == 0 {
		return in
	}
	out := make([]RouteInfo, 0, len(in))
	for _, r := range in {
		if callerSatisfies(caller, r.Access) {
			out = append(out, r)
		}
	}
	return out
}

func filterMCPs(in []MCPServerStatus, caller string) []MCPServerStatus {
	if len(in) == 0 {
		return in
	}
	out := make([]MCPServerStatus, 0, len(in))
	for _, m := range in {
		if callerSatisfies(caller, m.Access) {
			out = append(out, m)
		}
	}
	return out
}
