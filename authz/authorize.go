package authz

import (
	"context"

	"github.com/airlockrun/agentsdk"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/auth"
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
	validateRequirement(a, req)
	if p.Kind == KindRegisteredUser && p.UserID == uuid.Nil {
		return apperr.ErrUnauthorized
	}
	if !p.Valid() {
		return apperr.ErrForbidden
	}
	if p.Identity != nil {
		live, err := p.Identity.Resolve(ctx, q)
		if err != nil || live.Subject != p.UserID.String() {
			return apperr.ErrUnauthorized
		}
		p.TenantRole = auth.Role(live.TenantRole)
		if a != TenantSelfPasskeyManage && a != AccountSelfView && live.MustChangePassword {
			return apperr.ErrForbidden
		}
	}
	switch req.Axis {
	case AxisApp:
		return authorizeAppRuntime(ctx, q, p, agentID)
	case AxisAuthenticated:
		if !p.IsAuthenticatedUser() {
			return unauthenticatedOrForbidden(p)
		}
		return nil
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
		if a == AgentTestExecutor && p.Kind != KindCodegen {
			return apperr.ErrForbidden
		}
		if p.Kind == KindCodegen {
			if p.BuildID == uuid.Nil || p.CodegenAgentID == uuid.Nil || p.CodegenAgentID != agentID {
				return apperr.ErrForbidden
			}
			active, err := q.AgentBuildIntegrationActive(ctx, dbq.AgentBuildIntegrationActiveParams{
				ID:      dbqUUID(p.BuildID),
				AgentID: dbqUUID(agentID),
			})
			if err != nil {
				return err
			}
			if !active {
				return apperr.ErrForbidden
			}
			return nil
		}
		access, _, err := p.EffectiveAgentAccessChecked(ctx, q, agentID)
		if err != nil {
			return err
		}
		if !AccessAtLeast(access, req.Agent) {
			return apperr.ErrForbidden
		}
		return nil
	case AxisAgent:
		access, _, err := p.EffectiveAgentAccessChecked(ctx, q, agentID)
		if err != nil {
			return err
		}
		if !AccessAtLeast(access, req.Agent) {
			return apperr.ErrForbidden
		}
		return nil
	default:
		panic("authz: invalid policy axis")
	}
}

func validateRequirement(a Action, req Requirement) {
	switch req.Axis {
	case AxisTenant:
		if req.Tenant.Valid() && req.Agent == "" {
			return
		}
	case AxisAgent, AxisIntegration:
		if accessRank(req.Agent) >= 0 && req.Tenant == "" {
			return
		}
	case AxisAuthenticated, AxisApp:
		if req.Agent == "" && req.Tenant == "" {
			return
		}
	}
	panic("authz: invalid requirement for " + string(a))
}

func dbqUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

// AuthorizeResolvedAccess applies an agent-axis policy to a service-resolved
// access ceiling. It does not authenticate a caller or establish object ownership.
// Scoped conversation capabilities remain responsible for their object binding.
func AuthorizeResolvedAccess(a Action, access agentsdk.Access) error {
	req, ok := policy[a]
	if !ok {
		panic("authz: unknown action " + string(a))
	}
	validateRequirement(a, req)
	if req.Axis != AxisAgent {
		panic("authz: not an agent-axis action: " + string(a))
	}
	if !AccessAtLeast(access, req.Agent) {
		return apperr.ErrForbidden
	}
	return nil
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
	// Validate the action even for owners: ownership must not bypass a malformed contract.
	RequiredTenantRole(adminAction)
	if p.Identity != nil {
		if err := Authorize(ctx, q, p, ResourceView, uuid.Nil); err != nil {
			return err
		}
	}
	if p.IsAuthenticatedUser() && p.UserID == ownerID {
		return nil
	}
	return Authorize(ctx, q, p, adminAction, uuid.Nil)
}
