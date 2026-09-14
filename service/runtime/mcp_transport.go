package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/airlockrun/agentsdk/wire"
)

// callMCPTool does a stateless MCP interaction: connect → initialize → tools/call → disconnect.
func CallMCPTool(ctx context.Context, httpClient *http.Client, serverURL string, authInjection []byte, creds string, req wire.MCPToolCallRequest) (*wire.MCPToolCallResponse, error) {
	connectURL, headers, err := applyMCPAuth(serverURL, authInjection, creds)
	if err != nil {
		return nil, err
	}

	client, err := connectMCPHTTP(ctx, httpClient, connectURL, headers)
	if err != nil {
		return nil, fmt.Errorf("MCP connect: %w", err)
	}
	defer client.Close()

	found := false
	for _, candidate := range client.tools {
		if candidate.Name == req.Tool {
			found = true
			break
		}
	}
	if !found {
		return &wire.MCPToolCallResponse{
			Content: []wire.MCPContent{{Type: "text", Text: fmt.Sprintf("tool %q not found on MCP server", req.Tool)}},
			IsError: true,
		}, nil
	}

	result, err := client.CallTool(ctx, req.Tool, req.Arguments)
	if err != nil {
		return &wire.MCPToolCallResponse{
			Content: []wire.MCPContent{{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	return result, nil
}

// DiscoverMCPTools connects to a remote MCP server and returns its tool
// schemas plus the server-level `instructions` it advertised in the
// initialize result (empty when the server set none).
func DiscoverMCPTools(ctx context.Context, httpClient *http.Client, serverURL string, authInjection []byte, creds string) ([]McpToolInfo, string, error) {
	connectURL, headers, err := applyMCPAuth(serverURL, authInjection, creds)
	if err != nil {
		return nil, "", err
	}

	client, err := connectMCPHTTP(ctx, httpClient, connectURL, headers)
	if err != nil {
		return nil, "", fmt.Errorf("MCP connect for discovery: %w", err)
	}
	defer client.Close()

	return client.tools, client.instructions, nil
}

// mcpToolInfo is the internal representation of a discovered MCP tool.
type McpToolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// applyMCPAuth shapes (url, headers) for an outbound MCP HTTP call given the
// stored auth_injection config and decrypted credential. Empty creds return
// the inputs unchanged. Empty / unset Type defaults to bearer-in-header to
// preserve behavior for MCP servers registered before AuthInjection existed.
func applyMCPAuth(serverURL string, authInjection []byte, creds string) (string, map[string]string, error) {
	headers := map[string]string{}
	if creds == "" {
		return serverURL, headers, nil
	}

	var injection wire.AuthInjection
	if len(authInjection) > 0 {
		_ = json.Unmarshal(authInjection, &injection)
	}

	switch injection.Type {
	case "", wire.AuthInjectBearer:
		headers["Authorization"] = "Bearer " + creds
	case wire.AuthInjectAPIKey:
		name := injection.Name
		if name == "" {
			name = "X-API-Key"
		}
		headers[name] = creds
	case wire.AuthInjectQueryParam:
		u, err := url.Parse(serverURL)
		if err != nil {
			return "", nil, fmt.Errorf("parse MCP URL: %w", err)
		}
		name := injection.Name
		if name == "" {
			name = "token"
		}
		q := u.Query()
		q.Set(name, creds)
		u.RawQuery = q.Encode()
		serverURL = u.String()
	case wire.AuthInjectPathPrefix:
		u, err := url.Parse(serverURL)
		if err != nil {
			return "", nil, fmt.Errorf("parse MCP URL: %w", err)
		}
		u.Path = "/" + creds + u.Path
		serverURL = u.String()
	}
	return serverURL, headers, nil
}
