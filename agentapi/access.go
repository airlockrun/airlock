package agentapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

// MCPPrincipalKind discriminates how a caller hit the A2A MCP endpoint.
type MCPPrincipalKind int

const (
	// MCPPrincipalAnon means no JWT was presented.
	MCPPrincipalAnon MCPPrincipalKind = iota
	// MCPPrincipalUser means a user JWT was presented (web SPA path).
	// UserID is set.
	MCPPrincipalUser
	// MCPPrincipalAgent means an agent JWT was presented (sibling A2A
	// caller). CallerAgentID + ParentRunID are set; UserID is derived
	// from the parent run's conversation and also populated.
	MCPPrincipalAgent
	// MCPPrincipalOAuthClient means an OAuth-issued access token was
	// presented (external MCP client — Claude Desktop, Codex CLI,
	// etc.). UserID + ClientID are set. The audience binding (token
	// `aud` matches the target agent's canonical resource URL) is
	// verified upstream in resolvePrincipal, so this principal is
	// treated identically to MCPPrincipalUser for the access ladder.
	MCPPrincipalOAuthClient
)

// MCPPrincipal carries the caller identity for the MCP server endpoint.
// Built by the MCP handler from request headers / JWT and threaded into
// computeA2ACallerAccess.
type MCPPrincipal struct {
	Kind          MCPPrincipalKind
	UserID        uuid.UUID // anon: uuid.Nil; user/agent/oauth: original user
	CallerAgentID uuid.UUID // agent only
	ParentRunID   uuid.UUID // agent only
	ClientID      string    // oauth only — for audit / logging
}

// ErrMCPUnauthenticated means the caller presented no credentials and
// the target agent does not allow public MCP. The handler maps this to
// HTTP 401.
var ErrMCPUnauthenticated = errors.New("mcp: unauthenticated and target disallows public mcp")

// ErrMCPForbidden means the caller is authenticated but the target's
// access ladder rejects them (e.g. non-member on a non-member-closed
// target). The handler maps this to HTTP 403.
var ErrMCPForbidden = errors.New("mcp: access denied for target agent")

// computeA2ACallerAccess resolves the caller's effective access on the
// target agent's MCP endpoint by applying the same access ladder as
// chat: tenant role isn't consulted (agent_members is the only axis).
//
// For sibling-agent callers the agent's own identity is purely for
// audit/accounting — the principal is the *original user* (propagated
// from the parent run's conversation), and authorization is evaluated
// as if that user had hit the MCP endpoint directly. This is the
// natural delegation model: an agent's code runs with its user's
// privileges, no more.
func computeA2ACallerAccess(ctx context.Context, q *dbq.Queries, target dbq.Agent, principal MCPPrincipal) (agentsdk.Access, error) {
	switch principal.Kind {
	case MCPPrincipalAnon:
		if !target.AllowPublicMcp {
			return "", ErrMCPUnauthenticated
		}
		return agentsdk.AccessPublic, nil

	case MCPPrincipalUser, MCPPrincipalAgent, MCPPrincipalOAuthClient:
		// Both apply the same user-side ladder against the target. Agent
		// callers were already verified upstream: the caller's JWT
		// matches ParentRunID's agent_id, and the principal.UserID was
		// pulled from that run's conversation.user_id.
		userID := principal.UserID
		if userID == uuid.Nil {
			// Defensive: an agent JWT with no derivable original user
			// means the parent run is a cron/webhook trigger. v1 does
			// not allow A2A from those — agentsdk rejects upfront, but
			// belt-and-suspenders here.
			return "", fmt.Errorf("%w: no original user for caller", ErrMCPForbidden)
		}
		// One ladder for every surface: authz.EffectiveAgentAccess maps
		// (user, agent) → admin/user/public off agent_members. A member
		// resolves to AccessUser/AccessAdmin; a non-member resolves to
		// AccessPublic, which here is only honored if the target opens
		// itself to non-members — otherwise it's a 403. The non-member /
		// public-MCP flags are MCP-surface policy and stay here, not in
		// the shared ladder.
		access := authz.UserPrincipal(userID, "").EffectiveAgentAccess(ctx, q, uuid.UUID(target.ID.Bytes))
		if access == agentsdk.AccessPublic && !target.AllowNonMemberMcp {
			return "", ErrMCPForbidden
		}
		return access, nil

	default:
		return "", fmt.Errorf("%w: unknown principal kind", ErrMCPForbidden)
	}
}
