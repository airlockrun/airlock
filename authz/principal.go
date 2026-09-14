// Package authz is the single authorization layer every surface gates
// through. It models the caller as a Principal (registered user,
// anonymous human, or non-human trigger), resolves that principal's
// effective per-agent access off agent_grants, and checks it against a
// central action→required-level policy. HTTP handlers, bridges, MCP, and
// the system agent all build a Principal and call Authorize — there is
// no second place that decides "what level does this action need".
//
// It is a low-level package (deps: agentsdk, auth, dbq, apperr, uuid,
// pgtype) so both service and trigger can import it without a cycle.
package authz

import (
	"github.com/airlockrun/airlock/auth"
	"github.com/google/uuid"
)

// Kind distinguishes registered users, anonymous humans, and non-human callers.
type Kind int

const (
	// KindRegisteredUser — authenticated via a user JWT. UserID and
	// TenantRole are set.
	KindRegisteredUser Kind = iota
	// KindAnonymousUser — a human with no account (bridge public DM).
	// Resolves to AccessPublic; may do public-reachable actions but no
	// member/admin ones.
	KindAnonymousUser
	// KindTrigger — no human at all (cron/webhook). Cannot delegate as a
	// user; ordinary agent-axis actions are denied.
	KindTrigger
	// KindCodegen is an active agent build using its narrow integration
	// credential. It has no tenant or ordinary agent standing.
	KindCodegen
)

// Principal is the caller identity threaded through every gated call.
// Build it once at the surface boundary (handler / bridge / MCP) and
// pass it down; nothing below invents identity.
type Principal struct {
	Kind       Kind
	UserID     uuid.UUID      // RegisteredUser only; uuid.Nil otherwise
	TenantRole auth.Role      // RegisteredUser only
	Identity   *auth.Identity // Verified credential provenance; never a role/access override.

	// BuildID and CodegenAgentID are set only for KindCodegen. The integration
	// policy verifies both against the active build row on every service call.
	BuildID        uuid.UUID
	CodegenAgentID uuid.UUID
	appRunID       uuid.UUID
	appRunAgentID  uuid.UUID
}

// UserPrincipal builds a trusted internal policy principal, not a credential
// proof. Transport admission uses PrincipalFromClaims. A uuid.Nil id yields a
// principal that Authorize treats as unauthenticated (ErrUnauthorized).
func UserPrincipal(id uuid.UUID, role auth.Role) Principal {
	return Principal{Kind: KindRegisteredUser, UserID: id, TenantRole: role}
}

// PrincipalFromClaims preserves the admission proof for later live rechecks.
// Claims without verified admission cannot manufacture a registered identity.
func PrincipalFromClaims(claims *auth.Claims) Principal {
	if claims == nil || claims.Identity() == nil {
		return Principal{}
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil || id != claims.Identity().Provenance().UserID {
		return Principal{}
	}
	return Principal{Kind: KindRegisteredUser, UserID: id, TenantRole: auth.Role(claims.TenantRole), Identity: claims.Identity()}
}

// AnonymousPrincipal builds an anonymous-human principal (bridge public DM).
func AnonymousPrincipal() Principal {
	return Principal{Kind: KindAnonymousUser}
}

// TriggerPrincipal builds a non-human trigger principal (cron/webhook).
func TriggerPrincipal() Principal {
	return Principal{Kind: KindTrigger}
}

// CodegenPrincipal builds the narrow principal admitted only by integration
// policy actions while its build credential remains active.
func CodegenPrincipal(buildID, agentID uuid.UUID) Principal {
	return Principal{Kind: KindCodegen, BuildID: buildID, CodegenAgentID: agentID}
}

// IsAuthenticatedUser reports whether the principal is a registered user
// with a real UserID, the precondition for tenant-axis actions.
func (p Principal) IsAuthenticatedUser() bool {
	return p.Kind == KindRegisteredUser && p.UserID != uuid.Nil && p.Valid()
}

// Valid rejects unknown kinds and fields that belong to a different identity kind.
func (p Principal) Valid() bool {
	if p.Kind != KindTrigger && (p.appRunID != uuid.Nil || p.appRunAgentID != uuid.Nil) {
		return false
	}
	switch p.Kind {
	case KindRegisteredUser:
		return p.TenantRole.Valid() && p.BuildID == uuid.Nil && p.CodegenAgentID == uuid.Nil
	case KindAnonymousUser, KindTrigger:
		return p.Identity == nil && p.UserID == uuid.Nil && p.TenantRole == "" && p.BuildID == uuid.Nil && p.CodegenAgentID == uuid.Nil
	case KindCodegen:
		return p.Identity == nil && p.UserID == uuid.Nil && p.TenantRole == "" && p.BuildID != uuid.Nil && p.CodegenAgentID != uuid.Nil
	default:
		return false
	}
}
