package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/service"
	integrationservice "github.com/airlockrun/airlock/service/integrations"
	"github.com/airlockrun/sol/webfetch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maxIntegrationOutputBytes = MaxBufferedResponseBytes

func (h *Handler) RequestConnection(ctx context.Context, agentID uuid.UUID, slug string, req wire.ProxyRequest) (integrationservice.ConnectionResult, error) {
	q := dbq.New(h.db.Pool())
	conn, err := q.ResolveBoundConnection(ctx, dbq.ResolveBoundConnectionParams{AgentID: toPgUUID(agentID), Slug: slug})
	if errors.Is(err, pgx.ErrNoRows) {
		return integrationservice.ConnectionResult{}, service.Detail(service.ErrNotFound, "connection %q is not bound", slug)
	}
	if err != nil {
		return integrationservice.ConnectionResult{}, err
	}
	noAuth := conn.AuthMode == string(wire.ConnectionAuthNone)
	var creds string
	if !noAuth {
		creds, err = oauth.EnsureConnectionToken(ctx, h.db, h.encryptor, h.oauthClient, h.logger, toPgUUID(agentID), slug, conn.ID, time.Now())
		if errors.Is(err, oauth.ErrNeedsReauth) {
			return integrationservice.ConnectionResult{}, service.Detail(service.ErrConflict, "connection %q needs authorization", slug)
		}
		if err != nil {
			return integrationservice.ConnectionResult{}, fmt.Errorf("resolve connection credentials: %w", err)
		}
	}

	upstreamURL, err := connectionUpstreamURL(h.httpNetwork, conn.BaseUrl, req.Path)
	if err != nil {
		return integrationservice.ConnectionResult{}, service.Detail(service.ErrInvalidInput, "invalid upstream URL: %v", err)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	upstream, err := http.NewRequestWithContext(ctx, method, upstreamURL.String(), body)
	if err != nil {
		return integrationservice.ConnectionResult{}, service.Detail(service.ErrInvalidInput, "invalid upstream request: %v", err)
	}
	if req.Body != "" {
		upstream.Header.Set("Content-Type", "application/json")
	}
	upstream.Header.Set("User-Agent", webfetch.UserAgent)
	applyHeaderMap(upstream.Header, decodeConnHeaders(conn.Headers))
	applyHeaderMap(upstream.Header, req.Headers)
	if !noAuth {
		InjectAuth(upstream, conn.AuthInjection, creds)
	}

	resp, err := h.httpNetwork.Client(30 * time.Second).Do(upstream)
	if err != nil {
		return integrationservice.ConnectionResult{}, fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxIntegrationOutputBytes+1))
	if err != nil {
		return integrationservice.ConnectionResult{}, fmt.Errorf("read upstream response: %w", err)
	}
	if len(bodyBytes) > maxIntegrationOutputBytes {
		return integrationservice.ConnectionResult{}, service.Detail(service.ErrInvalidInput, "upstream response exceeds %d bytes", maxIntegrationOutputBytes)
	}
	headers := resp.Header.Clone()
	if creds != "" {
		bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(creds), []byte("[REDACTED]"))
		for name, values := range headers {
			for i, value := range values {
				values[i] = strings.ReplaceAll(value, creds, "[REDACTED]")
			}
			headers[name] = values
		}
	}
	return integrationservice.ConnectionResult{StatusCode: resp.StatusCode, Headers: headers, Body: bodyBytes}, nil
}

func (h *Handler) ListMCPTools(ctx context.Context, agentID uuid.UUID, slug string) (integrationservice.MCPTools, error) {
	server, err := dbq.New(h.db.Pool()).ResolveBoundMCPServer(ctx, dbq.ResolveBoundMCPServerParams{AgentID: toPgUUID(agentID), Slug: slug})
	if errors.Is(err, pgx.ErrNoRows) {
		return integrationservice.MCPTools{}, service.Detail(service.ErrNotFound, "MCP server %q is not bound", slug)
	}
	if err != nil {
		return integrationservice.MCPTools{}, err
	}
	var tools []wire.MCPToolSchema
	if err := json.Unmarshal(server.ToolSchemas, &tools); err != nil {
		return integrationservice.MCPTools{}, fmt.Errorf("decode cached MCP schemas: %w", err)
	}
	return integrationservice.MCPTools{Tools: tools, Instructions: server.ServerInstructions}, nil
}

func (h *Handler) CallMCPTool(ctx context.Context, agentID uuid.UUID, slug string, req wire.MCPToolCallRequest) (wire.MCPToolCallResponse, error) {
	if req.Tool == "" {
		return wire.MCPToolCallResponse{}, service.Detail(service.ErrInvalidInput, "tool is required")
	}
	q := dbq.New(h.db.Pool())
	server, err := q.ResolveBoundMCPServer(ctx, dbq.ResolveBoundMCPServerParams{AgentID: toPgUUID(agentID), Slug: slug})
	if errors.Is(err, pgx.ErrNoRows) {
		return wire.MCPToolCallResponse{}, service.Detail(service.ErrNotFound, "MCP server %q is not bound", slug)
	}
	if err != nil {
		return wire.MCPToolCallResponse{}, err
	}
	var creds string
	if server.AuthMode != string(wire.MCPAuthNone) {
		creds, err = oauth.EnsureMCPServerToken(ctx, h.db, h.encryptor, h.oauthClient, h.logger, toPgUUID(agentID), slug, server.ID, time.Now())
		if errors.Is(err, oauth.ErrNeedsReauth) {
			return wire.MCPToolCallResponse{}, service.Detail(service.ErrConflict, "MCP server %q needs authorization", slug)
		}
		if err != nil {
			return wire.MCPToolCallResponse{}, fmt.Errorf("resolve MCP credentials: %w", err)
		}
	}
	result, err := callMCPTool(ctx, h.httpNetwork.Client(60*time.Second), server.Url, server.AuthInjection, creds, req)
	if err != nil {
		return wire.MCPToolCallResponse{}, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return wire.MCPToolCallResponse{}, err
	}
	if len(encoded) > maxIntegrationOutputBytes {
		return wire.MCPToolCallResponse{}, service.Detail(service.ErrInvalidInput, "MCP response exceeds %d bytes", maxIntegrationOutputBytes)
	}
	if creds != "" {
		for i := range result.Content {
			result.Content[i].Text = strings.ReplaceAll(result.Content[i].Text, creds, "[REDACTED]")
			result.Content[i].URI = strings.ReplaceAll(result.Content[i].URI, creds, "[REDACTED]")
			result.Content[i].Data = strings.ReplaceAll(result.Content[i].Data, creds, "[REDACTED]")
		}
	}
	return *result, nil
}

var _ integrationservice.Backend = (*Handler)(nil)
