package agentapi

import "github.com/airlockrun/airlock/service/mcpaccess"

// MCPPrincipal retains the opaque credential proof throughout an MCP request.
type MCPPrincipal = mcpaccess.Principal

const (
	MCPPrincipalAnon        = mcpaccess.Anonymous
	MCPPrincipalUser        = mcpaccess.User
	MCPPrincipalOAuthClient = mcpaccess.OAuthClient
)
