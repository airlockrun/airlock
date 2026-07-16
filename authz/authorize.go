package authz

import (
	"context"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Authorize is the single gate. It looks the action up in the policy
// table and checks the principal against the required level on the
// action's axis. Returns:
//   - apperr.ErrUnauthorized when there is no authenticated identity
//     (a registered-user principal with a zero UserID — i.e. no JWT).
//   - apperr.ErrForbidden when the principal is known but ranks below
//     the requirement.
//   - nil when allowed.
//
// Panics on an action missing from the policy table (fail loud — a new
// action must not silently default to allowed). agentID is ignored for
// tenant-axis actions.
func Authorize(ctx context.Context, q *dbq.Queries, p Principal, a Action, agentID uuid.UUID) error {
	req, ok := policy[a]
	if !ok {
		panic("authz: unknown action " + string(a))
	}
	switch req.Axis {
	case AxisTenant:
		// Tenant actions require a real registered user; anonymous and
		// trigger principals have no tenant standing.
		if !p.IsAuthenticatedUser() {
			return unauthenticatedOrForbidden(p)
		}
		if !p.TenantRole.AtLeast(req.Tenant) {
			return apperr.ErrForbidden
		}
		return nil
	case AxisIntegration:
		if p.Kind == KindCodegen {
			if p.BuildID == uuid.Nil || p.CodegenAgentID == uuid.Nil || p.CodegenAgentID != agentID {
				return apperr.ErrForbidden
			}
			active, err := q.AgentBuildIntegrationActive(ctx, dbq.AgentBuildIntegrationActiveParams{
				ID:      dbqUUID(p.BuildID),
				AgentID: dbqUUID(agentID),
			})
			if err != nil || !active {
				return apperr.ErrForbidden
			}
			return nil
		}
		if p.Kind == KindRegisteredUser && p.UserID == uuid.Nil {
			return apperr.ErrUnauthorized
		}
		if !AccessAtLeast(p.EffectiveAgentAccess(ctx, q, agentID), req.Agent) {
			return apperr.ErrForbidden
		}
		return nil
	default: // AxisAgent
		// Preserve the "no JWT" 401 for a registered-user principal that
		// somehow carries no UserID; anonymous/trigger resolve to public
		// and simply fall below any member/admin requirement (403).
		if p.Kind == KindRegisteredUser && p.UserID == uuid.Nil {
			return apperr.ErrUnauthorized
		}
		if !AccessAtLeast(p.EffectiveAgentAccess(ctx, q, agentID), req.Agent) {
			return apperr.ErrForbidden
		}
		return nil
	}
}

func dbqUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

// unauthenticatedOrForbidden distinguishes "no credentials at all" (401)
// from "known principal, insufficient standing" (403) for tenant actions.
func unauthenticatedOrForbidden(p Principal) error {
	if p.Kind == KindRegisteredUser && p.UserID == uuid.Nil {
		return apperr.ErrUnauthorized
	}
	return apperr.ErrForbidden
}

// AuthorizeOwnedResource gates on "the caller owns the resource, OR
// the caller's tenant role satisfies adminAction." Use this anywhere a
// row has a single owner_id (bridges, platform_identities, OAuth
// grants) and an admin escape exists for cross-user moderation.
//
// ownerID is the UserID stored on the resource. adminAction must be a
// tenant-axis Action — the policy table is the single source of truth
// for who can act on someone else's resource.
//
// Returns nil if owner, otherwise the result of Authorize(adminAction).
// Anonymous / trigger principals fall through to Authorize, which
// rejects them with 401/403 as appropriate.
func AuthorizeOwnedResource(ctx context.Context, q *dbq.Queries, p Principal, ownerID uuid.UUID, adminAction Action) error {
	if p.Kind == KindRegisteredUser && p.UserID != uuid.Nil && p.UserID == ownerID {
		return nil
	}
	return Authorize(ctx, q, p, adminAction, uuid.Nil)
}
