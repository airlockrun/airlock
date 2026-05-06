package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/goai/mcp"
	"github.com/airlockrun/goai/tool"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

var mcpHTTPClient = &http.Client{Timeout: 60 * time.Second}

// UpsertMCPServer handles PUT /api/agent/mcp-servers/{slug}.
func (h *agentHandler) UpsertMCPServer(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeJSONError(w, http.StatusBadRequest, "slug is required")
		return
	}

	var def agentsdk.MCPDef
	if err := readJSON(r, &def); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// For oauth_discovery, resolve auth/token URLs + DCR registration
	// endpoint via RFC 9728/8414 discovery. Errors are non-fatal — store
	// the server anyway and let MCPOAuthStart re-try discovery lazily
	// the first time the operator clicks Authorize.
	registrationEndpoint := ""
	if def.AuthMode == agentsdk.MCPAuthOAuthDiscovery && def.AuthURL == "" {
		result, err := discoverMCPAuth(r.Context(), def.URL)
		if err != nil {
			h.logger.Warn("MCP OAuth discovery failed", zap.String("slug", slug), zap.Error(err))
		} else {
			def.AuthURL = result.AuthorizationURL
			def.TokenURL = result.TokenURL
			registrationEndpoint = result.RegistrationEndpoint
			if len(result.ScopesSupported) > 0 && len(def.Scopes) == 0 {
				def.Scopes = result.ScopesSupported
			}
		}
	}

	scopes := ""
	if len(def.Scopes) > 0 {
		b, _ := json.Marshal(def.Scopes)
		scopes = string(b)
	}

	authInjection, err := json.Marshal(def.AuthInjection)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid auth_injection")
		return
	}

	q := dbq.New(h.db.Pool())
	if _, err := q.UpsertMCPServer(r.Context(), dbq.UpsertMCPServerParams{
		AgentID:              toPgUUID(agentID),
		Slug:                 slug,
		Name:                 def.Name,
		Url:                  def.URL,
		AuthMode:             string(def.AuthMode),
		AuthUrl:              def.AuthURL,
		TokenUrl:             def.TokenURL,
		RegistrationEndpoint: registrationEndpoint,
		Scopes:               scopes,
		Access:               string(def.Access),
		AuthInjection:        authInjection,
	}); err != nil {
		h.logger.Error("upsert MCP server failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to register MCP server")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// MCPToolCall handles POST /api/agent/mcp/{slug}/tools/call.
// Stateless: connect → initialize → tools/call → disconnect.
func (h *agentHandler) MCPToolCall(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")

	var req agentsdk.MCPToolCallRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	q := dbq.New(h.db.Pool())
	server, err := q.GetMCPServerBySlug(r.Context(), dbq.GetMCPServerBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "MCP server not found")
			return
		}
		h.logger.Error("get MCP server failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to get MCP server")
		return
	}

	// No credentials → 402.
	if server.AccessTokenRef == "" {
		writeJSON(w, http.StatusPaymentRequired, map[string]string{
			"error":   "auth_required",
			"slug":    server.Slug,
			"authUrl": buildMCPAuthURL(h.publicURL, agentID, slug, server.AuthMode),
			"message": fmt.Sprintf("MCP server %q needs authorization", server.Name),
		})
		return
	}

	// Token expired → 402.
	if server.TokenExpiresAt.Valid && server.TokenExpiresAt.Time.Before(time.Now()) {
		writeJSON(w, http.StatusPaymentRequired, map[string]string{
			"error":   "auth_required",
			"slug":    server.Slug,
			"authUrl": buildMCPAuthURL(h.publicURL, agentID, slug, server.AuthMode),
			"message": fmt.Sprintf("MCP server %q authorization has expired", server.Name),
		})
		return
	}

	// Decrypt credentials.
	creds, err := h.encryptor.Get(r.Context(), "mcp/"+pgUUID(server.ID).String()+"/access_token", server.AccessTokenRef)
	if err != nil {
		h.logger.Error("decrypt MCP credentials failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to decrypt credentials")
		return
	}

	// Stateless MCP call.
	result, err := callMCPTool(r.Context(), server.Url, server.AuthInjection, creds, req)
	if err != nil {
		h.logger.Error("MCP tool call failed", zap.String("slug", slug), zap.String("tool", req.Tool), zap.Error(err))
		writeJSON(w, http.StatusOK, agentsdk.MCPToolCallResponse{
			Content: []agentsdk.MCPContent{{Type: "text", Text: "MCP error: " + err.Error()}},
			IsError: true,
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// mcpServerStatus holds auth status and tool count for an MCP server.
type mcpServerStatus struct {
	agentsdk.MCPAuthStatus
	ToolCount int
}

// discoverAllMCPStatus attempts tool discovery for all MCP servers that have credentials.
// Returns auth status and tool counts per server (for prompt display).
func (h *agentHandler) discoverAllMCPStatus(
	ctx context.Context,
	q *dbq.Queries,
	agentID uuid.UUID,
	servers []dbq.AgentMcpServer,
) []mcpServerStatus {
	var result []mcpServerStatus

	for _, server := range servers {
		if server.AccessTokenRef == "" {
			result = append(result, mcpServerStatus{
				MCPAuthStatus: agentsdk.MCPAuthStatus{
					Slug:       server.Slug,
					AuthMode:   agentsdk.MCPAuth(server.AuthMode),
					Authorized: false,
					AuthURL:    buildMCPAuthURL(h.publicURL, agentID, server.Slug, server.AuthMode),
				},
			})
			continue
		}

		creds, err := h.encryptor.Get(ctx, "mcp/"+pgUUID(server.ID).String()+"/access_token", server.AccessTokenRef)
		if err != nil {
			h.logger.Error("decrypt MCP credentials failed", zap.String("slug", server.Slug), zap.Error(err))
			continue
		}

		tools, err := discoverMCPTools(ctx, server.Url, server.AuthInjection, creds)
		if err != nil {
			h.logger.Warn("MCP tool discovery failed", zap.String("slug", server.Slug), zap.Error(err))
			result = append(result, mcpServerStatus{
				MCPAuthStatus: agentsdk.MCPAuthStatus{
					Slug:       server.Slug,
					AuthMode:   agentsdk.MCPAuth(server.AuthMode),
					Authorized: true,
				},
			})
			continue
		}

		// Store discovered schemas in DB for caching.
		schemasJSON, _ := json.Marshal(tools)
		_ = q.UpdateMCPServerToolSchemas(ctx, dbq.UpdateMCPServerToolSchemasParams{
			AgentID:     toPgUUID(agentID),
			Slug:        server.Slug,
			ToolSchemas: schemasJSON,
		})

		result = append(result, mcpServerStatus{
			MCPAuthStatus: agentsdk.MCPAuthStatus{
				Slug:       server.Slug,
				AuthMode:   agentsdk.MCPAuth(server.AuthMode),
				Authorized: true,
			},
			ToolCount: len(tools),
		})
	}

	return result
}

// callMCPTool does a stateless MCP interaction: connect → initialize → tools/call → disconnect.
func callMCPTool(ctx context.Context, serverURL string, authInjection []byte, creds string, req agentsdk.MCPToolCallRequest) (*agentsdk.MCPToolCallResponse, error) {
	connectURL, headers, err := applyMCPAuth(serverURL, authInjection, creds)
	if err != nil {
		return nil, err
	}

	client := mcp.NewClient()
	defer client.DisconnectAll()

	if err := client.Connect(ctx, mcp.ServerConfig{
		Name:      "proxy",
		Transport: "http",
		URL:       connectURL,
		Headers:   headers,
	}); err != nil {
		return nil, fmt.Errorf("MCP connect: %w", err)
	}

	// Find the tool and call it.
	tools := client.GetTools()
	// The tool name in the MCP server might be prefixed with "proxy_" by goai/mcp.
	// We need to find the tool by its original name.
	var targetTool *tool.Tool
	for _, t := range tools {
		// goai/mcp prefixes tool names with "{serverName}_", so our tool is "proxy_{originalName}".
		expectedName := "proxy_" + req.Tool
		if t.Name == expectedName {
			targetTool = &t
			break
		}
	}
	if targetTool == nil {
		return &agentsdk.MCPToolCallResponse{
			Content: []agentsdk.MCPContent{{Type: "text", Text: fmt.Sprintf("tool %q not found on MCP server", req.Tool)}},
			IsError: true,
		}, nil
	}

	result, err := targetTool.Execute(ctx, req.Arguments, tool.CallOptions{})
	if err != nil {
		return &agentsdk.MCPToolCallResponse{
			Content: []agentsdk.MCPContent{{Type: "text", Text: err.Error()}},
			IsError: true,
		}, nil
	}

	return &agentsdk.MCPToolCallResponse{
		Content: []agentsdk.MCPContent{{Type: "text", Text: result.Output}},
	}, nil
}

// discoverMCPTools connects to an MCP server, lists tools, and disconnects.
func discoverMCPTools(ctx context.Context, serverURL string, authInjection []byte, creds string) ([]mcpToolInfo, error) {
	connectURL, headers, err := applyMCPAuth(serverURL, authInjection, creds)
	if err != nil {
		return nil, err
	}

	client := mcp.NewClient()
	defer client.DisconnectAll()

	if err := client.Connect(ctx, mcp.ServerConfig{
		Name:      "discovery",
		Transport: "http",
		URL:       connectURL,
		Headers:   headers,
	}); err != nil {
		return nil, fmt.Errorf("MCP connect for discovery: %w", err)
	}

	tools := client.GetTools()
	result := make([]mcpToolInfo, 0, len(tools))
	for _, t := range tools.Ordered(nil) {
		// Strip the "discovery_" prefix added by goai/mcp.
		name := t.Name
		if len("discovery_") < len(name) && name[:len("discovery_")] == "discovery_" {
			name = name[len("discovery_"):]
		}
		result = append(result, mcpToolInfo{
			Name:        name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return result, nil
}

// mcpToolInfo is the internal representation of a discovered MCP tool.
type mcpToolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// discoverMCPAuth runs RFC 9728/8414 discovery on an MCP server URL.
func discoverMCPAuth(ctx context.Context, serverURL string) (*oauth.DiscoveryResult, error) {
	return oauth.DiscoverUpstream(ctx, mcpHTTPClient, serverURL)
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

	var injection agentsdk.AuthInjection
	if len(authInjection) > 0 {
		_ = json.Unmarshal(authInjection, &injection)
	}

	switch injection.Type {
	case "", agentsdk.AuthInjectBearer:
		headers["Authorization"] = "Bearer " + creds
	case agentsdk.AuthInjectAPIKey:
		name := injection.Name
		if name == "" {
			name = "X-API-Key"
		}
		headers[name] = creds
	case agentsdk.AuthInjectQueryParam:
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
	case agentsdk.AuthInjectPathPrefix:
		u, err := url.Parse(serverURL)
		if err != nil {
			return "", nil, fmt.Errorf("parse MCP URL: %w", err)
		}
		u.Path = "/" + creds + u.Path
		serverURL = u.String()
	}
	return serverURL, headers, nil
}

// buildMCPAuthURL returns an Airlock-hosted URL for users to authorize an MCP server.
func buildMCPAuthURL(publicURL string, agentID uuid.UUID, slug, authMode string) string {
	switch authMode {
	case "oauth", "oauth_discovery":
		return fmt.Sprintf("%s/api/v1/credentials/oauth/start?agent_id=%s&mcp_slug=%s",
			publicURL, agentID, slug)
	case "token":
		return fmt.Sprintf("%s/ui/credentials/new?agent_id=%s&mcp_slug=%s",
			publicURL, agentID, slug)
	default:
		return ""
	}
}
