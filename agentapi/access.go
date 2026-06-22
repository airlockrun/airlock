package agentapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
// target agent's MCP endpoint off the grant ladder: a caller is admitted
// only if a grant actually matches their grantee-set (a direct grant or a
// group, incl. the All-Users group = "shared with everyone"), and the level
// is that grant's role. The bare AccessPublic floor (no matching grant) is
// not admitted — that's what distinguishes an explicit All-Users `public`
// grant (admit at public) from a non-member (deny). The MCP master switch
// (mcp_enabled) and anonymous exposure (allow_public_mcp) are gated by the
// handlers; this function decides the per-caller level.
//
// A sibling-agent caller is evaluated for the driving user, then capped by
// the acting agent's owner (a sibling agent can never wield more authority
// than its own owner holds, even when a higher-privilege user drives the
// run) and by the per-edge max_access the operator set. Both can only lower
// access; the admit decision (a grant must match for BOTH the user and the
// owner) is made before the caps.
func computeA2ACallerAccess(ctx context.Context, q *dbq.Queries, target dbq.Agent, principal MCPPrincipal) (agentsdk.Access, error) {
	targetID := uuid.UUID(target.ID.Bytes)
	switch principal.Kind {
	case MCPPrincipalAnon:
		if !target.AllowPublicMcp {
			return "", ErrMCPUnauthenticated
		}
		return agentsdk.AccessPublic, nil

	case MCPPrincipalUser, MCPPrincipalOAuthClient:
		userID := principal.UserID
		if userID == uuid.Nil {
			return "", fmt.Errorf("%w: no original user for caller", ErrMCPForbidden)
		}
		access, granted := authz.UserPrincipal(userID, "").EffectiveAgentAccessGranted(ctx, q, targetID)
		if !granted {
			return "", ErrMCPForbidden
		}
		return access, nil

	case MCPPrincipalAgent:
		// Verified upstream: the caller's JWT matches ParentRunID's
		// agent_id, and principal.UserID was pulled from that run's
		// conversation.user_id.
		userID := principal.UserID
		if userID == uuid.Nil {
			// An agent JWT with no derivable original user means the parent
			// run is a cron/webhook trigger. v1 does not allow A2A from
			// those — agentsdk rejects upfront, belt-and-suspenders here.
			return "", fmt.Errorf("%w: no original user for caller", ErrMCPForbidden)
		}
		userAccess, userGranted := authz.UserPrincipal(userID, "").EffectiveAgentAccessGranted(ctx, q, targetID)
		actingAgent, err := q.GetAgentByID(ctx, toPgUUID(principal.CallerAgentID))
		if err != nil {
			return "", fmt.Errorf("%w: acting agent not found", ErrMCPForbidden)
		}
		ownerAccess, ownerGranted := authz.UserPrincipal(uuid.UUID(actingAgent.OwnerPrincipalID.Bytes), "").EffectiveAgentAccessGranted(ctx, q, targetID)
		// Admit only if both the driving user and the acting agent's owner
		// hold a grant on the target. Either lacking one means the
		// delegation has no authority to borrow.
		if !userGranted || !ownerGranted {
			return "", ErrMCPForbidden
		}
		entitlement := authz.MinAccess(userAccess, ownerAccess)
		// Per-edge max_access cap the operator set when adding the sibling.
		// Absent (a raw MCP call outside the caller's address book) means no
		// extra cap, preserving the owner/user-floored entitlement.
		maxAccess := agentsdk.AccessAdmin
		edge, err := q.GetSiblingMaxAccess(ctx, dbq.GetSiblingMaxAccessParams{
			ParentAgentID:  toPgUUID(principal.CallerAgentID),
			SiblingAgentID: target.ID,
		})
		switch {
		case err == nil:
			maxAccess = agentsdk.Access(edge)
		case errors.Is(err, pgx.ErrNoRows):
			// no declared edge — leave maxAccess at AccessAdmin (no cap)
		default:
			return "", fmt.Errorf("%w: read sibling edge", ErrMCPForbidden)
		}
		return authz.MinAccess(entitlement, maxAccess), nil

	default:
		return "", fmt.Errorf("%w: unknown principal kind", ErrMCPForbidden)
	}
}
