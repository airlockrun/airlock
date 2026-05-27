package service

import (
	"context"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// accessRank totally orders the three access levels so RequireAgentAccess
// can answer "is the caller's level high enough?" with one comparison.
func accessRank(a agentsdk.Access) int {
	switch a {
	case agentsdk.AccessAdmin:
		return 3
	case agentsdk.AccessUser:
		return 2
	case agentsdk.AccessPublic:
		return 1
	}
	return 0
}

// RequireAgentAccess gates a service call against the caller's per-agent
// access ladder. Returns:
//   - ErrUnauthorized when userID is the zero UUID (no JWT).
//   - ErrForbidden when the caller's resolved access is below `min`.
//
// The caller's level is computed by trigger.ResolveAgentAccess, which
// reads agent_members; non-members fall through to AccessPublic. This
// helper does NOT fetch the agent record — when the service also needs
// the row, call dbq.Queries.GetAgentByID separately. (Splitting the
// concerns preserves the existing 403-on-missing-agent semantics for
// handlers that never fetched: a non-existent agentID resolves to
// AccessPublic and bounces here rather than 404ing.)
func RequireAgentAccess(ctx context.Context, q *dbq.Queries, userID, agentID uuid.UUID, min agentsdk.Access) error {
	if userID == uuid.Nil {
		return ErrUnauthorized
	}
	if accessRank(trigger.ResolveAgentAccess(ctx, q, agentID, userID)) < accessRank(min) {
		return ErrForbidden
	}
	return nil
}

// RequireAgentLevel is RequireAgentAccess + a GetAgentByID fetch, for
// services that immediately need the agent row. A missing row maps to
// ErrNotFound (not ErrForbidden) — use this only on endpoints whose
// current behavior is to 404 a missing agentID.
func RequireAgentLevel(ctx context.Context, q *dbq.Queries, userID, agentID uuid.UUID, min agentsdk.Access) (dbq.Agent, error) {
	if userID == uuid.Nil {
		return dbq.Agent{}, ErrUnauthorized
	}
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return dbq.Agent{}, ErrNotFound
	}
	if accessRank(trigger.ResolveAgentAccess(ctx, q, agentID, userID)) < accessRank(min) {
		return dbq.Agent{}, ErrForbidden
	}
	return agent, nil
}

// ResolveAgent looks up an agent by either its UUID or its slug. Used
// by surfaces whose route param is shaped as `{identifier}` — the MCP
// JSON-RPC entry point and the OAuth Authorization Server endpoints.
// A2A sibling callers pass the rename-safe UUID; external MCP clients
// paste a config URL that typically carries the slug. Either form
// resolves to the same row.
func ResolveAgent(ctx context.Context, q *dbq.Queries, identifier string) (dbq.Agent, error) {
	if id, err := uuid.Parse(identifier); err == nil {
		return q.GetAgentByID(ctx, pgtype.UUID{Bytes: id, Valid: true})
	}
	return q.GetAgentBySlug(ctx, identifier)
}

// RequireTenantManager passes when the user's tenant role is manager or
// admin. Returns ErrUnauthorized for a zero userID and ErrForbidden for
// any role below manager (including "user" and the empty string).
func RequireTenantManager(ctx context.Context, q *dbq.Queries, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return ErrUnauthorized
	}
	u, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: userID, Valid: true})
	if err != nil {
		return ErrUnauthorized
	}
	if !auth.RoleAtLeast(u.TenantRole, "manager") {
		return ErrForbidden
	}
	return nil
}
