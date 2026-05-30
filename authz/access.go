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

// EffectiveAgentAccess resolves the principal's access on agentID off
// agent_members. It is the pure membership ladder: a member maps to
// AccessUser/AccessAdmin, everyone else (anonymous, trigger, non-member
// registered user) to AccessPublic. Surface-specific "is public allowed
// here" policy (the agent's allow_public_mcp / AllowPublicDMs flags)
// lives at the surface, not in this ladder.
func (p Principal) EffectiveAgentAccess(ctx context.Context, q *dbq.Queries, agentID uuid.UUID) agentsdk.Access {
	if p.Kind != KindRegisteredUser || p.UserID == uuid.Nil {
		return agentsdk.AccessPublic
	}
	member, err := q.GetAgentMember(ctx, dbq.GetAgentMemberParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
		UserID:  pgtype.UUID{Bytes: p.UserID, Valid: true},
	})
	if err != nil {
		return agentsdk.AccessPublic
	}
	if member.Role == "admin" {
		return agentsdk.AccessAdmin
	}
	return agentsdk.AccessUser
}
