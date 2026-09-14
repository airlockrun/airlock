package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/mcpaccess"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/airlock/trigger"
	"github.com/airlockrun/goai/mcp"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// MCPServer exposes registered app tools and resources without a model loop.
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
	s.serveDispatch(w, r, h, access, target, principal)
}

func (s *MCPServer) serveDispatch(w http.ResponseWriter, r *http.Request, h *Handler, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal) {
	var msg runtimesvc.JsonrpcMessage
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	if err := decoder.Decode(&msg); err != nil || msg.JSONRPC != "2.0" {
		writeJSONRPCError(w, nil, runtimesvc.RpcErrParse, "invalid JSON-RPC envelope")
		return
	}
	if decoder.Decode(new(any)) != io.EOF {
		writeJSONRPCError(w, nil, runtimesvc.RpcErrParse, "trailing JSON-RPC data")
		return
	}
	ctx := r.Context()
	switch msg.Method {
	case "initialize":
		s.handleInitialize(w, target, msg)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "notifications/cancelled":
		s.handleCancelled(ctx, access, target, principal, msg)
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		s.handleToolsList(ctx, w, access, target, principal, msg)
	case "tools/call":
		s.handleToolsCall(ctx, w, h, access, target, principal, msg)
	case "resources/list":
		s.handleResourcesList(ctx, w, h, access, target, principal, msg)
	case "resources/read":
		s.handleResourcesRead(ctx, w, h, access, target, principal, msg)
	case "resources/templates/list":
		s.handleResourcesTemplatesList(ctx, w, access, target, principal, msg)
	default:
		writeJSONRPCError(w, msg.ID, runtimesvc.RpcErrMethodNotFound, "unknown method: "+msg.Method)
	}
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

func (s *MCPServer) handleInitialize(w http.ResponseWriter, target dbq.Agent, msg runtimesvc.JsonrpcMessage) {
	title := target.Name
	if target.Emoji != "" {
		title = target.Emoji + " " + title
	}
	result, _ := json.Marshal(map[string]any{"protocolVersion": mcp.LatestProtocolVersion,
		"capabilities": map[string]any{"tools": map[string]any{"listChanged": false}, "resources": map[string]any{"subscribe": false, "listChanged": false}},
		"serverInfo":   map[string]any{"name": target.Slug, "title": title, "version": "1.0"}, "instructions": target.Description})
	writeJSONRPCResult(w, msg.ID, result)
}

func (s *MCPServer) handleToolsList(ctx context.Context, w http.ResponseWriter, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal, msg runtimesvc.JsonrpcMessage) {
	rows, err := access.ListTools(ctx, principal, uuid.UUID(target.ID.Bytes))
	if err != nil {
		writeJSONRPCError(w, msg.ID, runtimesvc.RpcErrInternal, "list tools")
		return
	}
	type entry struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}
	tools := make([]entry, 0, len(rows))
	for _, row := range rows {
		tools = append(tools, entry{row.Name, row.Description, row.InputSchema})
	}
	result, _ := json.Marshal(map[string]any{"tools": tools})
	writeJSONRPCResult(w, msg.ID, result)
}

func (s *MCPServer) handleToolsCall(ctx context.Context, w http.ResponseWriter, h *Handler, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal, msg runtimesvc.JsonrpcMessage) {
	if _, err := normalizeMCPRequestID(msg.ID); err != nil {
		writeJSONRPCError(w, msg.ID, runtimesvc.RpcErrInvalidRequest, "tools/call requires a string or number id")
		return
	}
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.Name == "" {
		writeJSONRPCError(w, msg.ID, runtimesvc.RpcErrInvalidParams, "invalid tool call")
		return
	}
	targetID := uuid.UUID(target.ID.Bytes)
	selected, err := access.Tool(ctx, principal, targetID, params.Name)
	if err != nil {
		writeJSONRPCError(w, msg.ID, runtimesvc.RpcErrMethodNotFound, "unknown tool: "+params.Name)
		return
	}
	if len(params.Arguments) == 0 {
		params.Arguments = json.RawMessage(`{}`)
	}
	if !json.Valid(params.Arguments) {
		writeJSONRPCError(w, msg.ID, runtimesvc.RpcErrInvalidParams, "invalid arguments")
		return
	}
	rc := &rewriterCtx{ctx: ctx, s3: h.s3}
	result, _, invokeErr := access.CallTool(ctx, principal, targetID, msg.ID, params.Name, params.Arguments, s.dispatcher, h.runtime, func(callCtx context.Context, files *mcpaccess.RunFiles, input json.RawMessage) (json.RawMessage, error) {
		rc.ctx, rc.files = callCtx, files
		prepared, err := materializeInbound(rc, input, selected.InputSchema)
		if err != nil {
			return nil, errors.New(err.Message)
		}
		return prepared, nil
	})
	// The execution context ends with CallTool; response file reads revalidate
	// the credential and ownership using the still-live HTTP request context.
	rc.ctx = ctx
	body := []byte(result.Output)
	if invokeErr != nil {
		body = []byte(invokeErr.Error())
	} else if json.Valid(body) {
		var err *runtimesvc.MaterializeError
		body, err = materializeOutbound(rc, body, selected.OutputSchema)
		if err != nil {
			writeJSONRPCError(w, msg.ID, err.Code, err.Message)
			return
		}
	}
	content := []map[string]any{{"type": "text", "text": string(body)}}
	content = append(content, rc.extraContent...)
	if invokeErr == nil {
		for _, attachment := range result.Attachments {
			path, ok := strings.CutPrefix(attachment.Data, "s3ref:")
			if !ok {
				writeJSONRPCError(w, msg.ID, runtimesvc.RpcErrInternal, "invalid attachment reference")
				return
			}
			file, err := rc.files.Resolve(ctx, path)
			if err != nil {
				writeJSONRPCError(w, msg.ID, runtimesvc.RpcErrInternal, "attachment unavailable")
				return
			}
			url, err := h.s3.PublicPresignGetURL(ctx, file.S3Key, time.Hour)
			if err != nil {
				writeJSONRPCError(w, msg.ID, runtimesvc.RpcErrInternal, "attachment unavailable")
				return
			}
			content = append(content, map[string]any{"type": "resource_link", "uri": url, "name": attachment.Filename, "mimeType": attachment.MimeType})
		}
	}
	payload, _ := json.Marshal(map[string]any{"content": content, "isError": invokeErr != nil})
	writeJSONRPCResult(w, msg.ID, payload)
}

func normalizeMCPRequestID(raw json.RawMessage) ([]byte, error) {
	return mcpaccess.NormalizeRequestID(raw)
}

func (s *MCPServer) handleCancelled(ctx context.Context, access *mcpaccess.Service, target dbq.Agent, principal MCPPrincipal, msg runtimesvc.JsonrpcMessage) {
	var params struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(msg.Params, &params) != nil {
		return
	}
	if err := access.Cancel(ctx, principal, uuid.UUID(target.ID.Bytes), params.RequestID); err != nil {
		s.logger.Debug("MCP cancellation denied or inactive", zap.Error(err))
	}
}

func writeJSONRPCResult(w http.ResponseWriter, id, result json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(runtimesvc.JsonrpcMessage{JSONRPC: "2.0", ID: id, Result: result})
}

func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, text string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(runtimesvc.JsonrpcMessage{JSONRPC: "2.0", ID: id, Error: &runtimesvc.JsonrpcError{Code: code, Message: text}})
}
