package agentapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/goai/mcp"
)

const maxMCPHTTPResponseBytes = 20 << 20

type mcpHTTPClient struct {
	client          *http.Client
	url             string
	headers         map[string]string
	protocolVersion string
	sessionID       string
	nextID          int64
	instructions    string
	tools           []mcpToolInfo
}

func connectMCPHTTP(ctx context.Context, client *http.Client, serverURL string, headers map[string]string) (*mcpHTTPClient, error) {
	if client == nil {
		panic("agentapi: MCP HTTP client is required")
	}
	c := &mcpHTTPClient{
		client:          client,
		url:             serverURL,
		headers:         headers,
		protocolVersion: mcp.LatestProtocolVersion,
	}
	connected := false
	defer func() {
		if !connected {
			_ = c.Close()
		}
	}()
	result, err := c.send(ctx, "initialize", map[string]any{
		"protocolVersion": mcp.LatestProtocolVersion,
		"capabilities": map[string]any{
			"tools":     map[string]any{},
			"resources": map[string]any{"subscribe": true},
		},
		"clientInfo": map[string]any{"name": "goai", "version": "1.0.0"},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize failed: %w", err)
	}
	var initialized struct {
		Instructions    string `json:"instructions"`
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(result, &initialized); err != nil {
		return nil, fmt.Errorf("decode initialize response: %w", err)
	}
	c.instructions = initialized.Instructions
	if initialized.ProtocolVersion != "" {
		if !supportedMCPProtocolVersion(initialized.ProtocolVersion) {
			return nil, fmt.Errorf("server's protocol version is not supported: %s", initialized.ProtocolVersion)
		}
		c.protocolVersion = initialized.ProtocolVersion
	}
	if _, err := c.send(ctx, "notifications/initialized", nil); err != nil {
		return nil, fmt.Errorf("initialized notification failed: %w", err)
	}
	if err := c.listTools(ctx); err != nil {
		return nil, fmt.Errorf("list tools failed: %w", err)
	}
	// Resource discovery is part of the standard handshake, but this proxy only
	// exposes tools. Servers are allowed not to implement resources/list.
	_, _ = c.send(ctx, "resources/list", nil)
	connected = true
	return c, nil
}

func supportedMCPProtocolVersion(version string) bool {
	for _, candidate := range mcp.SupportedProtocolVersions {
		if candidate == version {
			return true
		}
	}
	return false
}

func (c *mcpHTTPClient) listTools(ctx context.Context) error {
	result, err := c.send(ctx, "tools/list", nil)
	if err != nil {
		return err
	}
	var response struct {
		Tools []mcpToolInfo `json:"tools"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return err
	}
	byName := make(map[string]mcpToolInfo, len(response.Tools))
	for _, tool := range response.Tools {
		if _, exists := byName[tool.Name]; exists {
			return fmt.Errorf("MCP tools/list returned duplicate tool name %q", tool.Name)
		}
		byName[tool.Name] = tool
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	c.tools = make([]mcpToolInfo, 0, len(names))
	for _, name := range names {
		c.tools = append(c.tools, byName[name])
	}
	return nil
}

func (c *mcpHTTPClient) CallTool(ctx context.Context, name string, arguments json.RawMessage) (*wire.MCPToolCallResponse, error) {
	var args map[string]any
	if err := json.Unmarshal(arguments, &args); err != nil {
		return nil, err
	}
	result, err := c.send(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	var response struct {
		Content []struct {
			Type        string `json:"type"`
			Text        string `json:"text,omitempty"`
			Data        string `json:"data,omitempty"`
			MimeType    string `json:"mimeType,omitempty"`
			URI         string `json:"uri,omitempty"`
			Name        string `json:"name,omitempty"`
			Description string `json:"description,omitempty"`
			Resource    *struct {
				URI      string `json:"uri"`
				MimeType string `json:"mimeType,omitempty"`
				Text     string `json:"text,omitempty"`
				Blob     string `json:"blob,omitempty"`
			} `json:"resource,omitempty"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, err
	}
	if response.IsError {
		if len(response.Content) > 0 {
			return nil, fmt.Errorf("tool error: %s", response.Content[0].Text)
		}
		return nil, errors.New("tool error")
	}

	var text strings.Builder
	attachments := make([]wire.MCPContent, 0, len(response.Content))
	for _, content := range response.Content {
		switch content.Type {
		case "text":
			text.WriteString(content.Text)
		case "image":
			if content.Data != "" {
				attachments = append(attachments, wire.MCPContent{Type: "image", MimeType: content.MimeType, Data: content.Data})
			}
		case "resource":
			if content.Resource == nil {
				continue
			}
			if content.Resource.Text != "" {
				text.WriteString(content.Resource.Text)
			}
			if content.Resource.Blob != "" {
				kind := "resource"
				if strings.HasPrefix(content.Resource.MimeType, "image/") {
					kind = "image"
				}
				attachments = append(attachments, wire.MCPContent{Type: kind, MimeType: content.Resource.MimeType, Data: content.Resource.Blob})
			}
		case "resource_link":
			if text.Len() > 0 {
				text.WriteByte('\n')
			}
			label := content.Name
			if label == "" {
				label = content.URI
			}
			if content.Description != "" {
				fmt.Fprintf(&text, "[Resource: %s — %s — %s]", label, content.URI, content.Description)
			} else {
				fmt.Fprintf(&text, "[Resource: %s — %s]", label, content.URI)
			}
		}
	}
	contents := make([]wire.MCPContent, 0, 1+len(attachments))
	if text.Len() > 0 {
		contents = append(contents, wire.MCPContent{Type: "text", Text: text.String()})
	}
	contents = append(contents, attachments...)
	return &wire.MCPToolCallResponse{Content: contents}, nil
}

func (c *mcpHTTPClient) send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	notification := strings.HasPrefix(method, "notifications/")
	request := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int64  `json:"id,omitempty"`
		Method  string `json:"method"`
		Params  any    `json:"params,omitempty"`
	}{JSONRPC: "2.0", Method: method, Params: params}
	if !notification {
		c.nextID++
		request.ID = c.nextID
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	c.setHeaders(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if sessionID := resp.Header.Get(mcp.HeaderSessionID); sessionID != "" {
		c.sessionID = sessionID
	}
	if notification {
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			return nil, mcpHTTPStatusError(resp)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	}
	if resp.StatusCode == http.StatusAccepted {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, mcpHTTPStatusError(resp)
	}
	contentType := resp.Header.Get("Content-Type")
	switch {
	case strings.Contains(contentType, "application/json"):
		raw, err := readBoundedMCPResponse(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		return parseMCPJSONResponse(raw, c.nextID)
	case strings.Contains(contentType, "text/event-stream"):
		return parseMCPSSE(responseLimitReader{reader: bufio.NewReader(resp.Body)}, c.nextID)
	default:
		return nil, fmt.Errorf("MCP HTTP transport: unexpected content type %q", contentType)
	}
}

func (c *mcpHTTPClient) setHeaders(req *http.Request) {
	for name, value := range c.headers {
		req.Header.Set(name, value)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(mcp.HeaderProtocolVersion, c.protocolVersion)
	if c.sessionID != "" {
		req.Header.Set(mcp.HeaderSessionID, c.sessionID)
	}
	userAgent := req.Header.Get("User-Agent")
	if userAgent == "" {
		req.Header.Set("User-Agent", mcp.UserAgentSuffix)
	} else if !strings.Contains(userAgent, mcp.UserAgentSuffix) {
		req.Header.Set("User-Agent", userAgent+" "+mcp.UserAgentSuffix)
	}
}

func (c *mcpHTTPClient) Close() error {
	if c.sessionID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url, nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func mcpHTTPStatusError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return fmt.Errorf("MCP HTTP transport: POST returned HTTP %d: %s", resp.StatusCode, string(body))
}

func readBoundedMCPResponse(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxMCPHTTPResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMCPHTTPResponseBytes {
		return nil, fmt.Errorf("MCP HTTP response exceeds %d bytes", maxMCPHTTPResponseBytes)
	}
	return body, nil
}

func parseMCPJSONResponse(raw []byte, requestID int64) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("MCP HTTP transport: empty response body")
	}
	if trimmed[0] != '[' {
		return parseMCPMessage(trimmed)
	}
	var messages []jsonrpcMessage
	if err := json.Unmarshal(trimmed, &messages); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC response array: %w", err)
	}
	wantID, _ := json.Marshal(requestID)
	for _, message := range messages {
		if bytes.Equal(bytes.TrimSpace(message.ID), wantID) {
			return mcpMessageResult(message)
		}
	}
	return nil, fmt.Errorf("MCP HTTP transport: response missing id %d", requestID)
}

func parseMCPMessage(raw []byte) (json.RawMessage, error) {
	var message jsonrpcMessage
	if err := json.Unmarshal(raw, &message); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC response: %w", err)
	}
	return mcpMessageResult(message)
}

func mcpMessageResult(message jsonrpcMessage) (json.RawMessage, error) {
	if message.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", message.Error.Code, message.Error.Message)
	}
	return message.Result, nil
}

type responseLimitReader struct {
	reader *bufio.Reader
	read   int
}

func (r *responseLimitReader) readLine() (string, error) {
	line, err := r.reader.ReadString('\n')
	r.read += len(line)
	if r.read > maxMCPHTTPResponseBytes {
		return "", fmt.Errorf("MCP HTTP response exceeds %d bytes", maxMCPHTTPResponseBytes)
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), err
}

func parseMCPSSE(reader responseLimitReader, requestID int64) (json.RawMessage, error) {
	var eventType string
	var data []string
	for {
		line, err := reader.readLine()
		if line == "" {
			if eventType == "" || eventType == "message" {
				raw := []byte(strings.Join(data, "\n"))
				if len(raw) > 0 {
					var message jsonrpcMessage
					if json.Unmarshal(raw, &message) == nil {
						wantID, _ := json.Marshal(requestID)
						if bytes.Equal(bytes.TrimSpace(message.ID), wantID) {
							return mcpMessageResult(message)
						}
					}
				}
			}
			eventType = ""
			data = data[:0]
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("MCP HTTP transport: SSE stream closed before matching response")
			}
			return nil, err
		}
		switch {
		case strings.HasPrefix(line, "event:"):
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
}
