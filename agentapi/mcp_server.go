package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/mcpaccess"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"
)

const inboundMCPProtocol = "2026-07-28"

// MCPServer exposes request-scoped app capabilities through stateless MCP.
type MCPServer struct {
	dispatcher *trigger.Dispatcher
	logger     *zap.Logger
}

func NewMCPServer(dispatcher *trigger.Dispatcher, logger *zap.Logger) *MCPServer {
	if dispatcher == nil || logger == nil {
		panic("MCP server: dispatcher and logger are required")
	}
	return &MCPServer{dispatcher: dispatcher, logger: logger}
}
func (s *MCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request, h *Handler) {
	s.serve(w, r, h, false)
}
func (s *MCPServer) ServePublicHTTP(w http.ResponseWriter, r *http.Request, h *Handler) {
	s.serve(w, r, h, true)
}

func (s *MCPServer) serve(w http.ResponseWriter, r *http.Request, h *Handler, public bool) {
	identifier := chi.URLParam(r, "identifier")
	token, supplied, err := auth.RequestBearerToken(r)
	if err != nil {
		writeMCPAuthError(w, h.publicURL, identifier, errInvalidToken)
		return
	}
	access := mcpaccess.New(h.db, h.publicURL)
	target, principal, err := access.Admit(r.Context(), h.jwtSecret, token, supplied, identifier, public)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, service.ErrForbidden):
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			writeMCPAuthError(w, h.publicURL, identifier, err)
		}
		return
	}
	server := s.protocolServer(h, access, target, principal)
	if r.Header.Get("Mcp-Protocol-Version") != inboundMCPProtocol {
		http.Error(w, "MCP protocol 2026-07-28 is required", http.StatusBadRequest)
		return
	}
	mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, PropagateRequestCancellation: true, MaxRequestBodyBytes: 16 << 20,
	}).ServeHTTP(w, r)
}

func (s *MCPServer) protocolServer(h *Handler, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal) *mcp.Server {
	title := target.Name
	if target.Emoji != "" {
		title = target.Emoji + " " + title
	}
	server := mcp.NewServer(&mcp.Implementation{Name: target.Slug, Title: title, Version: "1.0"}, &mcp.ServerOptions{
		Instructions: target.Description, SupportedProtocolVersions: []string{inboundMCPProtocol},
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}, Resources: &mcp.ResourceCapabilities{}},
		SetCacheable: func(_ context.Context, _ mcp.Request, c *mcp.Cacheable) { c.TTLMs = 0; c.CacheScope = "private" },
	})
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, request mcp.Request) (mcp.Result, error) {
			switch method {
			case "tools/list":
				return s.listTools(ctx, access, target, principal)
			case "tools/call":
				return s.callTool(ctx, h, access, target, principal, request.(*mcp.CallToolRequest).Params)
			case "resources/list":
				return s.listResources(ctx, h, access, target, principal)
			case "resources/read":
				return s.readResource(ctx, h, access, target, principal, request.(*mcp.ReadResourceRequest).Params.URI)
			case "resources/templates/list":
				return s.listResourceTemplates(ctx, access, target, principal)
			case "server/discover", "ping":
				return next(ctx, method, request)
			default:
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "unsupported MCP method: " + method}
			}
		}
	})
	return server
}

func (s *MCPServer) listTools(ctx context.Context, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal) (*mcp.ListToolsResult, error) {
	rows, err := access.ListTools(ctx, principal, uuid.UUID(target.ID.Bytes))
	if err != nil {
		return nil, err
	}
	tools := make([]*mcp.Tool, 0, len(rows))
	for _, row := range rows {
		tools = append(tools, &mcp.Tool{Name: row.Name, Description: row.Description, InputSchema: row.InputSchema, OutputSchema: row.OutputSchema})
	}
	return &mcp.ListToolsResult{Tools: tools, Cacheable: mcp.Cacheable{CacheScope: "private"}}, nil
}

func (s *MCPServer) callTool(ctx context.Context, h *Handler, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal, params *mcp.CallToolParamsRaw) (*mcp.CallToolResult, error) {
	if params.Name == "" {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "tool name is required"}
	}
	targetID := uuid.UUID(target.ID.Bytes)
	selected, err := access.Tool(ctx, principal, targetID, params.Name)
	if err != nil {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "unknown tool: " + params.Name}
	}
	input := params.Arguments
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	rc := &rewriterCtx{ctx: ctx, s3: h.s3}
	result, _, invokeErr := access.CallTool(ctx, principal, targetID, params.Name, input, s.dispatcher, h.runtime, func(callCtx context.Context, files *mcpaccess.RunFiles, input json.RawMessage) (json.RawMessage, error) {
		rc.ctx, rc.files = callCtx, files
		prepared, err := materializeInbound(rc, input, selected.InputSchema)
		if err != nil {
			return nil, errors.New(err.Message)
		}
		return prepared, nil
	})
	rc.ctx = ctx
	body := []byte(result.Output)
	if invokeErr != nil {
		body = []byte(invokeErr.Error())
	} else if json.Valid(body) {
		prepared, err := materializeOutbound(rc, body, selected.OutputSchema)
		if err != nil {
			return nil, &jsonrpc.Error{Code: int64(err.Code), Message: err.Message}
		}
		body = prepared
	}
	content := []map[string]any{{"type": "text", "text": string(body)}}
	content = append(content, rc.extraContent...)
	if invokeErr == nil {
		for _, attachment := range result.Attachments {
			path, ok := strings.CutPrefix(attachment.Data, "s3ref:")
			if !ok {
				return nil, errors.New("invalid attachment reference")
			}
			file, err := rc.files.Resolve(ctx, path)
			if err != nil {
				return nil, err
			}
			url, err := h.s3.PublicPresignGetURL(ctx, file.S3Key, time.Hour)
			if err != nil {
				return nil, err
			}
			content = append(content, map[string]any{"type": "resource_link", "uri": url, "name": attachment.Filename, "mimeType": attachment.MimeType})
		}
	}
	encoded, err := json.Marshal(map[string]any{"content": content, "isError": invokeErr != nil})
	if err != nil {
		return nil, err
	}
	var response mcp.CallToolResult
	if err := json.Unmarshal(encoded, &response); err != nil {
		return nil, err
	}
	if invokeErr == nil && json.Valid(body) {
		response.StructuredContent = json.RawMessage(body)
	}
	return &response, nil
}

var (
	errInvalidToken      = mcpaccess.ErrInvalidToken
	errAudienceMismatch  = mcpaccess.ErrAudienceMismatch
	errInsufficientScope = mcpaccess.ErrInsufficientScope
)

func writeMCPAuthError(w http.ResponseWriter, publicURL, identifier string, cause error) {
	resource := fmt.Sprintf("%s/.well-known/oauth-protected-resource/api/agent/%s/mcp", strings.TrimRight(publicURL, "/"), identifier)
	code, description, status := "invalid_token", "", http.StatusUnauthorized
	switch {
	case errors.Is(cause, errAudienceMismatch):
		description = "audience mismatch"
	case errors.Is(cause, errInsufficientScope):
		code, description, status = "insufficient_scope", "scope `mcp` required", http.StatusForbidden
	}
	header := fmt.Sprintf(`Bearer realm="MCP", resource_metadata="%s", error="%s"`, resource, code)
	if description != "" {
		header += fmt.Sprintf(`, error_description="%s"`, description)
	}
	w.Header().Set("WWW-Authenticate", header)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
