package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// MCPToolCall handles POST /api/agent/mcp/{slug}/tools/call.
// Stateless: connect → initialize → tools/call → disconnect.
func (h *Handler) MCPToolCall(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")

	var req wire.MCPToolCallRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	q := dbq.New(h.db.Pool())
	// Resolve the agent's mcp_server need to its bound resource; credentials
	// below key on the resolved server's own id.
	server, err := q.ResolveBoundMCPServer(r.Context(), dbq.ResolveBoundMCPServerParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "MCP server not bound")
			return
		}
		h.logger.Error("resolve MCP server failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to get MCP server")
		return
	}

	// Resolve credentials with on-demand refresh (see ServiceProxy): an
	// expired token is renewed here under a row lock, so it self-heals on this
	// call instead of waiting for the background tick. Only an unrecoverable
	// server (no token / no refresh token / provider-revoked) returns 402.
	var creds string
	if server.AuthMode != string(wire.MCPAuthNone) {
		creds, err = oauth.EnsureMCPServerToken(r.Context(), h.db, h.encryptor, h.oauthClient, h.logger, server.ID, time.Now())
		switch {
		case errors.Is(err, oauth.ErrNeedsReauth):
			writeJSON(w, http.StatusPaymentRequired, map[string]string{
				"error":   "auth_required",
				"slug":    server.Slug,
				"authUrl": buildMCPAuthURL(h.publicURL, agentID, slug, server.AuthMode),
				"message": fmt.Sprintf("MCP server %q needs authorization", server.Name),
			})
			return
		case err != nil:
			h.logger.Warn("resolve MCP token failed", zap.String("slug", slug), zap.Error(err))
			writeJSONError(w, http.StatusBadGateway, "failed to obtain MCP credentials")
			return
		}
	}

	// Stateless MCP call.
	result, err := callMCPTool(r.Context(), h.httpNetwork.Client(60*time.Second), server.Url, server.AuthInjection, creds, req)
	if err != nil {
		h.logger.Error("MCP tool call failed", zap.String("slug", slug), zap.String("tool", req.Tool), zap.Error(err))
		writeJSON(w, http.StatusOK, wire.MCPToolCallResponse{
			Content: []wire.MCPContent{{Type: "text", Text: "MCP error: " + err.Error()}},
			IsError: true,
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// mcpServerStatus holds auth status and tool count for an MCP server.
type mcpServerStatus struct {
	wire.MCPAuthStatus
	ToolCount int
}

// discoverAllMCPStatus attempts tool discovery for all MCP servers that have credentials.
// Returns auth status and tool counts per server (for prompt display).
func (h *Handler) discoverAllMCPStatus(
	ctx context.Context,
	q *dbq.Queries,
	agentID uuid.UUID,
	servers []dbq.ListBoundMCPServersByAgentRow,
) []mcpServerStatus {
	var result []mcpServerStatus

	for _, server := range servers {
		noAuth := server.AuthMode == string(wire.MCPAuthNone)
		if !noAuth && server.AccessTokenRef == "" {
			result = append(result, mcpServerStatus{
				MCPAuthStatus: wire.MCPAuthStatus{
					Slug:       server.Slug,
					AuthMode:   wire.MCPAuth(server.AuthMode),
					Authorized: false,
					AuthURL:    buildMCPAuthURL(h.publicURL, agentID, server.Slug, server.AuthMode),
				},
			})
			continue
		}

		var creds string
		if !noAuth {
			var err error
			creds, err = h.encryptor.Get(ctx, "mcp/"+pgUUID(server.ID).String()+"/access_token", server.AccessTokenRef)
			if err != nil {
				h.logger.Error("decrypt MCP credentials failed", zap.String("slug", server.Slug), zap.Error(err))
				continue
			}
		}

		tools, instructions, err := DiscoverMCPTools(ctx, h.httpNetwork.Client(60*time.Second), server.Url, server.AuthInjection, creds)
		if err != nil {
			h.logger.Warn("MCP tool discovery failed", zap.String("slug", server.Slug), zap.Error(err))
			result = append(result, mcpServerStatus{
				MCPAuthStatus: wire.MCPAuthStatus{
					Slug:       server.Slug,
					AuthMode:   wire.MCPAuth(server.AuthMode),
					Authorized: true,
				},
			})
			continue
		}

		// Store discovered schemas + server-level instructions in DB for
		// caching (durable across syncs without a re-handshake).
		schemasJSON, _ := json.Marshal(tools)
		_ = q.UpdateMCPServerToolSchemasByID(ctx, dbq.UpdateMCPServerToolSchemasByIDParams{
			ID:                 server.ID,
			ToolSchemas:        schemasJSON,
			ServerInstructions: instructions,
		})

		result = append(result, mcpServerStatus{
			MCPAuthStatus: wire.MCPAuthStatus{
				Slug:         server.Slug,
				AuthMode:     wire.MCPAuth(server.AuthMode),
				Authorized:   true,
				Instructions: instructions,
			},
			ToolCount: len(tools),
		})
	}

	return result
}

// callMCPTool does a stateless MCP interaction: connect → initialize → tools/call → disconnect.
func callMCPTool(ctx context.Context, httpClient *http.Client, serverURL string, authInjection []byte, creds string, req wire.MCPToolCallRequest) (*wire.MCPToolCallResponse, error) {
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
func DiscoverMCPTools(ctx context.Context, httpClient *http.Client, serverURL string, authInjection []byte, creds string) ([]mcpToolInfo, string, error) {
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
type mcpToolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// DiscoverMCPAuth runs RFC 9728/8414 discovery on an MCP server URL.
func DiscoverMCPAuth(ctx context.Context, httpClient *http.Client, serverURL string) (*oauth.DiscoveryResult, error) {
	return oauth.DiscoverUpstream(ctx, httpClient, serverURL)
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
