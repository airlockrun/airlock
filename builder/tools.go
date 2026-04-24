package builder

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/goai/mcp"
	"github.com/airlockrun/goai/tool"
)

// mcpProbeInput is the input schema for mcp_probe.
type mcpProbeInput struct {
	URL string `json:"url" jsonschema:"required,description=The MCP server URL to probe for capabilities and auth requirements"`
}

// mcpProbeResult is the output of mcp_probe.
type mcpProbeResult struct {
	URL                  string   `json:"url"`
	RecommendedAuthMode  string   `json:"recommendedAuthMode"`
	AuthorizationURL     string   `json:"authorizationUrl,omitempty"`
	TokenURL             string   `json:"tokenUrl,omitempty"`
	ScopesSupported      []string `json:"scopesSupported,omitempty"`
	Tools                []string `json:"tools,omitempty"`
	Error                string   `json:"error,omitempty"`
}

// newMCPProbeTool creates a tool that probes an MCP server URL for capabilities and auth requirements.
func newMCPProbeTool() tool.Tool {
	return tool.New("mcp_probe").
		Description("Probe an MCP server URL to discover its auth requirements and available tools. "+
			"Use this before writing RegisterMCP code to determine the correct AuthMode.").
		SchemaFromStruct(mcpProbeInput{}).
		Execute(func(ctx context.Context, input json.RawMessage, opts tool.CallOptions) (tool.Result, error) {
			var in mcpProbeInput
			if err := json.Unmarshal(input, &in); err != nil {
				return tool.Result{Output: "Error: invalid input: " + err.Error()}, nil
			}
			if in.URL == "" {
				return tool.Result{Output: "Error: url is required"}, nil
			}

			result := mcpProbeResult{URL: in.URL}

			// Step 1: Try RFC 9728/8414 discovery.
			discoveryResult, err := oauth.DiscoverUpstream(ctx, probeHTTPClient, in.URL)
			if err == nil {
				result.RecommendedAuthMode = "oauth_discovery"
				result.AuthorizationURL = discoveryResult.AuthorizationURL
				result.TokenURL = discoveryResult.TokenURL
				result.ScopesSupported = discoveryResult.ScopesSupported
			}

			// Step 2: Try unauthenticated MCP connect to list tools.
			mcpClient := mcp.NewClient()
			connectErr := mcpClient.Connect(ctx, mcp.ServerConfig{
				Name:      "probe",
				Transport: "http",
				URL:       in.URL,
			})
			if connectErr == nil {
				tools := mcpClient.GetTools()
				for _, t := range tools.Ordered(nil) {
					name := t.Name
					// Strip "probe_" prefix added by goai/mcp.
					if len(name) > 6 && name[:6] == "probe_" {
						name = name[6:]
					}
					result.Tools = append(result.Tools, name+": "+t.Description)
				}
				mcpClient.DisconnectAll()
				if result.RecommendedAuthMode == "" {
					result.RecommendedAuthMode = "none"
				}
			} else {
				if result.RecommendedAuthMode == "" {
					// No discovery, can't connect unauthenticated → likely needs auth.
					result.RecommendedAuthMode = "token"
					result.Error = "Could not connect without auth: " + connectErr.Error()
				}
			}

			out, _ := json.MarshalIndent(result, "", "  ")
			return tool.Result{Output: string(out)}, nil
		}).
		Build()
}

var probeHTTPClient = &http.Client{Timeout: 15 * time.Second}

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
