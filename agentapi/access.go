package agentapi

import (
	"context"
	"encoding/json"
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

var errMCPObjectNotAccessible = errors.New("mcp: object not accessible")

type mcpConversationMetadata struct {
	Principal string `json:"mcpPrincipal"`
}

// continuationPrincipalKey binds an MCP-created conversation to the complete
// request identity. Agent callers are run-bound; OAuth callers are client-bound.
// Anonymous callers have no stable identity and therefore cannot continue.
func continuationPrincipalKey(principal MCPPrincipal) (string, bool) {
	switch principal.Kind {
	case MCPPrincipalUser:
		if principal.UserID != uuid.Nil {
			return "user/" + principal.UserID.String(), true
		}
	case MCPPrincipalOAuthClient:
		if principal.UserID != uuid.Nil && principal.ClientID != "" {
			return "oauth/" + principal.UserID.String() + "/" + principal.ClientID, true
		}
	case MCPPrincipalAgent:
		if principal.UserID != uuid.Nil && principal.CallerAgentID != uuid.Nil && principal.ParentRunID != uuid.Nil {
			return "agent/" + principal.UserID.String() + "/" + principal.CallerAgentID.String() + "/" + principal.ParentRunID.String(), true
		}
	}
	return "", false
}

func continuationMetadata(principal MCPPrincipal) ([]byte, error) {
	key, ok := continuationPrincipalKey(principal)
	if !ok {
		return nil, errMCPObjectNotAccessible
	}
	return json.Marshal(mcpConversationMetadata{Principal: key})
}

func conversationBoundToPrincipal(conv dbq.AgentConversation, targetID uuid.UUID, principal MCPPrincipal) bool {
	if !conv.AgentID.Valid || uuid.UUID(conv.AgentID.Bytes) != targetID || conv.Source != "a2a" {
		return false
	}
	key, ok := continuationPrincipalKey(principal)
	if !ok {
		return false
	}
	if !conv.UserID.Valid || uuid.UUID(conv.UserID.Bytes) != principal.UserID {
		return false
	}
	var metadata mcpConversationMetadata
	return json.Unmarshal(conv.Metadata, &metadata) == nil && metadata.Principal == key
}

func getBoundMCPConversation(ctx context.Context, q *dbq.Queries, targetID uuid.UUID, principal MCPPrincipal, contextID string) (dbq.AgentConversation, error) {
	id, err := uuid.Parse(contextID)
	if err != nil {
		return dbq.AgentConversation{}, errMCPObjectNotAccessible
	}
	conv, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(id), AgentID: toPgUUID(targetID),
	})
	if err != nil || !conversationBoundToPrincipal(conv, targetID, principal) {
		return dbq.AgentConversation{}, errMCPObjectNotAccessible
	}
	return conv, nil
}

func getBoundMCPTask(ctx context.Context, q *dbq.Queries, targetID uuid.UUID, principal MCPPrincipal, taskID, contextID string) (dbq.Run, dbq.AgentConversation, error) {
	id, err := uuid.Parse(taskID)
	if err != nil {
		return dbq.Run{}, dbq.AgentConversation{}, errMCPObjectNotAccessible
	}
	run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{
		ID: toPgUUID(id), AgentID: toPgUUID(targetID),
	})
	if err != nil || run.Status != "suspended" || run.TriggerType != "a2a" || run.TriggerRef == "" {
		return dbq.Run{}, dbq.AgentConversation{}, errMCPObjectNotAccessible
	}
	if contextID != "" && contextID != run.TriggerRef {
		return dbq.Run{}, dbq.AgentConversation{}, errMCPObjectNotAccessible
	}
	if principal.Kind == MCPPrincipalAgent {
		if !run.ParentRunID.Valid {
			return dbq.Run{}, dbq.AgentConversation{}, errMCPObjectNotAccessible
		}
		originalParentID := uuid.UUID(run.ParentRunID.Bytes)
		boundPrincipal := principal
		boundPrincipal.ParentRunID = originalParentID
		conv, err := getBoundMCPConversation(ctx, q, targetID, boundPrincipal, run.TriggerRef)
		if err != nil || !agentRunCanResumeTask(ctx, q, principal, originalParentID) {
			return dbq.Run{}, dbq.AgentConversation{}, errMCPObjectNotAccessible
		}
		return run, conv, nil
	} else if run.ParentRunID.Valid {
		return dbq.Run{}, dbq.AgentConversation{}, errMCPObjectNotAccessible
	}
	conv, err := getBoundMCPConversation(ctx, q, targetID, principal, run.TriggerRef)
	if err != nil {
		return dbq.Run{}, dbq.AgentConversation{}, errMCPObjectNotAccessible
	}
	return run, conv, nil
}

func claimMCPTaskResume(ctx context.Context, q *dbq.Queries, run dbq.Run) error {
	claimed, err := q.ClaimMCPTaskResume(ctx, dbq.ClaimMCPTaskResumeParams{
		ID:         run.ID,
		AgentID:    run.AgentID,
		TriggerRef: run.TriggerRef,
	})
	if err != nil || claimed != 1 {
		return errMCPObjectNotAccessible
	}
	return nil
}

func agentRunCanResumeTask(ctx context.Context, q *dbq.Queries, principal MCPPrincipal, originalParentID uuid.UUID) bool {
	if principal.ParentRunID == originalParentID {
		return true
	}
	current, err := q.GetRunByID(ctx, toPgUUID(principal.ParentRunID))
	if err != nil || current.Status != "running" || uuid.UUID(current.AgentID.Bytes) != principal.CallerAgentID {
		return false
	}
	userID, err := chaseOriginalUser(ctx, q, current)
	if err != nil || userID != principal.UserID {
		return false
	}
	var input struct {
		ResumeRunID string `json:"resumeRunId"`
	}
	return json.Unmarshal(current.InputPayload, &input) == nil && input.ResumeRunID == originalParentID.String()
}

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
		// The declared sibling edge is both an admission requirement and the
		// operator-set max_access cap. Raw MCP calls outside the caller's
		// address book have no delegation authority.
		edge, err := q.GetSiblingMaxAccess(ctx, dbq.GetSiblingMaxAccessParams{
			ParentAgentID:  toPgUUID(principal.CallerAgentID),
			SiblingAgentID: target.ID,
		})
		if err != nil {
			return "", fmt.Errorf("%w: read sibling edge", ErrMCPForbidden)
		}
		return authz.MinAccess(entitlement, agentsdk.Access(edge)), nil

	default:
		return "", fmt.Errorf("%w: unknown principal kind", ErrMCPForbidden)
	}
}
