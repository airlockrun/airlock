package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// accessRank totally orders the three access levels. AccessAdmin >
// AccessUser > AccessPublic; unknown values are invalid.
func accessRank(a agentsdk.Access) int {
	switch a {
	case agentsdk.AccessAdmin:
		return 2
	case agentsdk.AccessUser:
		return 1
	case agentsdk.AccessPublic:
		return 0
	default:
		return -1
	}
}

// AccessAtLeast reports whether a ranks at or above min on the per-agent
// access ladder. The single comparator for that ladder — chat slash
// gates, the service-layer Authorize gate, and the MCP path all rank
// through here so the ordering can't drift between surfaces.
func AccessAtLeast(a, min agentsdk.Access) bool {
	return accessRank(a) >= 0 && accessRank(min) >= 0 && accessRank(a) >= accessRank(min)
}

// EffectiveAgentAccessChecked resolves grants and propagates lookup/admission
// failures. An absent grant is public; an unavailable lookup is an error.
// The access is the maximum across matching user and role-group grants. The
// boolean distinguishes an explicit public grant from the non-member floor.
func (p Principal) EffectiveAgentAccessChecked(ctx context.Context, q *dbq.Queries, agentID uuid.UUID) (agentsdk.Access, bool, error) {
	if !p.Valid() || agentID == uuid.Nil || p.Kind == KindTrigger || p.Kind == KindCodegen || p.Kind == KindRegisteredUser && p.UserID == uuid.Nil {
		return "", false, apperr.ErrForbidden
	}
	if p.Identity != nil {
		live, err := p.Identity.Resolve(ctx, q)
		if err != nil {
			return "", false, err
		}
		if live.Subject != p.UserID.String() {
			return "", false, apperr.ErrUnauthorized
		}
		if err := auth.RequireSecuredAccount(live); err != nil {
			return "", false, err
		}
		p.TenantRole = auth.Role(live.TenantRole)
	}
	set := p.GranteeSet()
	if len(set) == 0 {
		return agentsdk.AccessPublic, false, nil
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
		return "", false, err
	}
	if len(roles) == 0 {
		return agentsdk.AccessPublic, false, nil
	}
	best := agentsdk.AccessPublic
	for _, role := range roles {
		switch role {
		case "admin", "user", "public":
			if AccessAtLeast(agentsdk.Access(role), best) {
				best = agentsdk.Access(role)
			}
		default:
			return "", false, fmt.Errorf("invalid persisted agent access %q", role)
		}
	}
	return best, true, nil
}

// EffectiveAgentAccessForStoredUser resolves access for a persisted recipient,
// not a caller credential. Notification routing uses it to recheck the live
// account and grants without constructing authority outside this package.
func EffectiveAgentAccessForStoredUser(ctx context.Context, q *dbq.Queries, userID, agentID uuid.UUID) (agentsdk.Access, error) {
	if userID == uuid.Nil || agentID == uuid.Nil {
		return "", apperr.ErrForbidden
	}
	user, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: userID, Valid: true})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", apperr.ErrForbidden
	}
	if err != nil {
		return "", err
	}
	role := auth.Role(user.TenantRole)
	if user.MustChangePassword || !role.Valid() {
		return "", apperr.ErrForbidden
	}
	access, _, err := UserPrincipal(userID, role).EffectiveAgentAccessChecked(ctx, q, agentID)
	return access, err
}
