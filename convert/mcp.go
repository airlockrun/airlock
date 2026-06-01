package convert

import (
	"fmt"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	connsvc "github.com/airlockrun/airlock/service/connections"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MCPServerToProto maps the connections service MCPServer DTO to
// the wire MCPServerInfo. auth_url is derived from publicURL +
// agentID + slug; empty for non-interactive auth modes.
func MCPServerToProto(m connsvc.MCPServer, publicURL, agentID string) *airlockv1.MCPServerInfo {
	out := &airlockv1.MCPServerInfo{
		Id:          m.ID.String(),
		Slug:        m.Slug,
		Name:        m.Name,
		Url:         m.URL,
		AuthMode:    m.AuthMode,
		Authorized:  m.Authorized,
		HasOauthApp: m.HasOAuthApp,
		ToolCount:   int32(m.ToolCount),
		AuthUrl:     BuildMCPAuthURL(publicURL, agentID, m.Slug, m.AuthMode),
	}
	if m.TokenExpiresAt != nil {
		out.TokenExpiresAt = timestamppb.New(*m.TokenExpiresAt)
	}
	if m.LastSyncedAt != nil {
		out.LastSyncedAt = timestamppb.New(*m.LastSyncedAt)
	}
	return out
}

// MCPStatusToProto maps the MCPStatus service DTO to the wire
// MCPStatusInfo. No URLs, no metadata — just configured + name.
func MCPStatusToProto(s connsvc.MCPStatus) *airlockv1.MCPStatusInfo {
	return &airlockv1.MCPStatusInfo{
		Slug:       s.Slug,
		Name:       s.Name,
		AuthMode:   s.AuthMode,
		Authorized: s.Authorized,
	}
}

// BuildMCPAuthURL returns the airlock-hosted URL operators visit
// to authorize an MCP server. Empty for non-interactive auth modes.
func BuildMCPAuthURL(publicURL, agentID, slug, authMode string) string {
	switch authMode {
	case "oauth", "oauth_discovery":
		return fmt.Sprintf("%s/api/v1/credentials/oauth/start?agent_id=%s&mcp_slug=%s", publicURL, agentID, slug)
	case "token":
		return fmt.Sprintf("%s/ui/credentials/new?agent_id=%s&mcp_slug=%s", publicURL, agentID, slug)
	default:
		return ""
	}
}
