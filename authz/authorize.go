package authz

import (
	"context"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
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

// unauthenticatedOrForbidden distinguishes "no credentials at all" (401)
// from "known principal, insufficient standing" (403) for tenant actions.
func unauthenticatedOrForbidden(p Principal) error {
	if p.Kind == KindRegisteredUser && p.UserID == uuid.Nil {
		return apperr.ErrUnauthorized
	}
	return apperr.ErrForbidden
}
