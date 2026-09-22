package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/goai/mcp"
)

type McpHTTPClient struct {
	session      *mcp.Session
	instructions string
	tools        []McpToolInfo
}

func connectMCPHTTP(ctx context.Context, client *http.Client, serverURL string, headers map[string]string) (*McpHTTPClient, error) {
	s, err := mcp.Connect(ctx, mcp.ServerConfig{ClientName: "airlock", Transport: "http", URL: serverURL, Headers: headers, HTTPClient: client})
	if err != nil {
		return nil, err
	}
	c := &McpHTTPClient{session: s, instructions: s.Instructions()}
	if err := c.ListTools(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return c, nil
}

func (c *McpHTTPClient) ListTools(ctx context.Context) error {
	definitions, err := c.session.ListTools(ctx)
	if err != nil {
		return err
	}
	tools := make([]McpToolInfo, 0, len(definitions))
	for _, definition := range definitions {
		input, err := json.Marshal(definition.InputSchema)
		if err != nil {
			return err
		}
		var output json.RawMessage
		if definition.OutputSchema != nil {
			output, err = json.Marshal(definition.OutputSchema)
			if err != nil {
				return err
			}
		}
		tools = append(tools, McpToolInfo{Name: definition.Name, Description: definition.Description, InputSchema: input, OutputSchema: output})
	}
	c.tools = tools
	return nil
}

func (c *McpHTTPClient) CallTool(ctx context.Context, name string, arguments json.RawMessage) (*wire.MCPToolCallResponse, error) {
	result, err := c.session.CallTool(ctx, name, arguments)
	if err != nil {
		return nil, err
	}
	if result.NeedsInput() {
		return nil, errors.New("MCP tool requires additional input; call is incomplete")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	var response wire.MCPToolCallResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (c *McpHTTPClient) Close() error { return c.session.Close() }
