// Package authz is the single authorization layer every surface gates
// through. It models the caller as a Principal (registered user,
// anonymous human, or non-human trigger), resolves that principal's
// effective per-agent access off agent_grants, and checks it against a
// central action→required-level policy. HTTP handlers, bridges, A2A, and
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

// Kind discriminates how a caller was authenticated. It exists to kill
// the old userID==uuid.Nil ambiguity, which conflated "anonymous human"
// with "no human at all".
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
	// user; agent-axis actions and A2A initiation are denied.
	KindTrigger
)

// Principal is the caller identity threaded through every gated call.
// Build it once at the surface boundary (handler / bridge / A2A) and
// pass it down; nothing below invents identity.
type Principal struct {
	Kind       Kind
	UserID     uuid.UUID // RegisteredUser only; uuid.Nil otherwise
	TenantRole auth.Role // RegisteredUser only

	// OnBehalfOfAgent records the agent whose code is acting (A2A /
	// system-agent delegation). Audit/logging only — authorization
	// evaluates the delegated principal as the originating user, no more.
	OnBehalfOfAgent uuid.UUID
}

// UserPrincipal builds a registered-user principal. A uuid.Nil id yields
// a principal that Authorize treats as unauthenticated (ErrUnauthorized).
func UserPrincipal(id uuid.UUID, role auth.Role) Principal {
	return Principal{Kind: KindRegisteredUser, UserID: id, TenantRole: role}
}

// AnonymousPrincipal builds an anonymous-human principal (bridge public DM).
func AnonymousPrincipal() Principal {
	return Principal{Kind: KindAnonymousUser}
}

// TriggerPrincipal builds a non-human trigger principal (cron/webhook).
func TriggerPrincipal() Principal {
	return Principal{Kind: KindTrigger}
}

// IsAuthenticatedUser reports whether the principal is a registered user
// with a real UserID — the precondition for tenant-axis actions and for
// initiating A2A.
func (p Principal) IsAuthenticatedUser() bool {
	return p.Kind == KindRegisteredUser && p.UserID != uuid.Nil
}
