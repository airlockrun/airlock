package authz

import (
	"context"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// accessRank totally orders the three access levels. AccessAdmin >
// AccessUser > AccessPublic; anything unknown ranks at the floor.
func accessRank(a agentsdk.Access) int {
	switch a {
	case agentsdk.AccessAdmin:
		return 2
	case agentsdk.AccessUser:
		return 1
	default:
		return 0
	}
}

// AccessAtLeast reports whether a ranks at or above min on the per-agent
// access ladder. The single comparator for that ladder — chat slash
// gates, the service-layer Authorize gate, and the MCP path all rank
// through here so the ordering can't drift between surfaces.
func AccessAtLeast(a, min agentsdk.Access) bool {
	return accessRank(a) >= accessRank(min)
}

// MinAccess returns the lower of two access levels on the agent ladder. It
// is the A2A delegation ceiling: a sibling agent acting on a user's behalf
// can never exceed the access its own owner holds on the target, so the
// effective access is the minimum of (driving user, acting-agent owner).
func MinAccess(a, b agentsdk.Access) agentsdk.Access {
	if accessRank(a) <= accessRank(b) {
		return a
	}
	return b
}

// EffectiveAgentAccess resolves the principal's access on agentID off
// agent_grants. A grant may target the principal's own user id (per-user
// member) or a role-group in its grantee-set (e.g. the built-in `user` group =
// every registered user, "shared with everyone"); the effective access is the
// max role across all matching grants. Everyone with no matching grant
// (anonymous, trigger, non-member registered user) maps to AccessPublic.
// Surface-specific "is public allowed here" policy (the agent's allow_public_mcp
// / AllowPublicDMs flags) lives at the surface, not in this ladder.
func (p Principal) EffectiveAgentAccess(ctx context.Context, q *dbq.Queries, agentID uuid.UUID) agentsdk.Access {
	set := p.GranteeSet()
	if len(set) == 0 {
		return agentsdk.AccessPublic
	}
	grantees := make([]pgtype.UUID, len(set))
	for i, id := range set {
		grantees[i] = pgtype.UUID{Bytes: id, Valid: true}
	}
	roles, err := q.ListAgentGrantsForGrantees(ctx, dbq.ListAgentGrantsForGranteesParams{
		AgentID:    pgtype.UUID{Bytes: agentID, Valid: true},
		GranteeIds: grantees,
	})
	if err != nil {
		return agentsdk.AccessPublic
	}
	best := agentsdk.AccessPublic
	for _, role := range roles {
		switch role {
		case "admin":
			return agentsdk.AccessAdmin
		case "user":
			best = agentsdk.AccessUser
		}
	}
	return best
}
