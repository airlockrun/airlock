package appruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/oauth"
	"github.com/jackc/pgx/v5"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// mcpServerStatus holds auth status and tool count for an MCP server.
type mcpServerStatus struct {
	wire.MCPAuthStatus
	ToolCount int
}

// discoverAllMCPStatus attempts tool discovery for all MCP servers that have credentials.
// Returns auth status and tool counts per server (for prompt display).
func (h *Service) discoverAllMCPStatus(
	ctx context.Context,
	q *dbq.Queries,
	agentID uuid.UUID,
	servers []dbq.ListBoundMCPServersByAgentRow,
) ([]mcpServerStatus, error) {
	var result []mcpServerStatus
	// Different apps can bind the same resources under opposite slug orders.
	// Acquire every resource in UUID order before discovery updates any of them.
	servers = slices.Clone(servers)
	slices.SortFunc(servers, func(a, b dbq.ListBoundMCPServersByAgentRow) int {
		return strings.Compare(pgUUID(a.ID).String(), pgUUID(b.ID).String())
	})
	for _, server := range servers {
		if _, err := q.GetMCPServerByIDForUpdate(ctx, server.ID); err != nil {
			return nil, err
		}
	}

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

		tools, instructions, err := runtimesvc.DiscoverMCPTools(ctx, h.httpNetwork.Client(60*time.Second), server.Url, server.AuthInjection, creds)
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
		schemasJSON, err := json.Marshal(tools)
		if err != nil {
			return nil, err
		}
		if err := q.UpdateMCPServerToolSchemasByID(ctx, dbq.UpdateMCPServerToolSchemasByIDParams{
			ID:                 server.ID,
			ToolSchemas:        schemasJSON,
			ServerInstructions: instructions,
		}); err != nil {
			return nil, err
		}

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

	return result, nil
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

func (h *Service) MCPToolCall(ctx context.Context, slug string, req wire.MCPToolCallRequest) (*wire.MCPToolCallResponse, error) {
	agentID, err := h.admit(ctx, dbq.New(h.db.Pool()))
	if err != nil {
		return nil, err
	}
	q := dbq.New(h.db.Pool())
	// Resolve the agent's mcp_server need to its bound resource; credentials
	// below key on the resolved server's own id.
	server, err := q.ResolveBoundMCPServer(ctx, dbq.ResolveBoundMCPServerParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperr.Detail(apperr.ErrNotFound, "MCP server not bound")
		}
		h.logger.Error("resolve MCP server failed", zap.Error(err))
		return nil, fmt.Errorf("%s: %w", "failed to get MCP server", ErrUpstream)
	}
	// Resolve credentials with on-demand refresh (see ServiceProxy): an
	// expired token is renewed here under a row lock, so it self-heals on this
	// call instead of waiting for the background tick. Only an unrecoverable
	// server (no token / no refresh token / provider-revoked) returns 402.
	var creds string
	if server.AuthMode != string(wire.MCPAuthNone) {
		creds, err = oauth.EnsureMCPServerToken(ctx, h.db, h.encryptor, h.oauthClient, h.logger, toPgUUID(agentID), slug, server.ID, time.Now())
		switch {
		case errors.Is(err, oauth.ErrNeedsReauth):
			return nil, &AuthorizationRequired{Details: map[string]string{
				"error":   "auth_required",
				"slug":    server.Slug,
				"authUrl": buildMCPAuthURL(h.publicURL, agentID, slug, server.AuthMode),
				"message": fmt.Sprintf("MCP server %q needs authorization", server.Name),
			}}
		case err != nil:
			h.logger.Warn("resolve MCP token failed", zap.String("slug", slug), zap.Error(err))
			return nil, fmt.Errorf("%s: %w", "failed to obtain MCP credentials", ErrUpstream)
		}
	}

	// Stateless MCP call.
	result, err := runtimesvc.CallMCPTool(ctx, h.httpNetwork.Client(60*time.Second), server.Url, server.AuthInjection, creds, req)
	if err != nil {
		h.logger.Error("MCP tool call failed", zap.String("slug", slug), zap.String("tool", req.Tool), zap.Error(err))
		return &wire.MCPToolCallResponse{
			Content: []wire.MCPContent{{Type: "text", Text: "MCP error: " + err.Error()}},
			IsError: true,
		}, nil
	}

	return result, nil
}
