package authz

import (
	"github.com/airlockrun/airlock/auth"
	"github.com/google/uuid"
)

// Resource capabilities (the management plane). Runtime "use" of a bound
// resource is intrinsic to the agent's code and is not gated here; these gate
// who may see, attach (bind), and reconfigure a resource.
const (
	CapView   = "view"
	CapBind   = "bind"
	CapManage = "manage"
)

// Built-in group principal ids in the schema baseline. They let a grant
// target a tenant role ("all managers") without a stored-membership table: the
// resolver expands a caller into the role-groups it belongs to. admin ⊇
// manager ⊇ user, so a higher role inherits the lower groups' grants.
var (
	GroupAdmin   = uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	GroupManager = uuid.MustParse("00000000-0000-0000-0000-0000000000a2")
	GroupUser    = uuid.MustParse("00000000-0000-0000-0000-0000000000a3")
)

// Grant is a resource_grants row reduced to what a capability check needs.
type Grant struct {
	GranteeID    uuid.UUID
	Capabilities []string
}

// GranteeSet returns the principal ids a grant may target to reach p: p's own
// user id plus the built-in role-groups its tenant role belongs to. A grant to
// the `user` group reaches everyone; to `manager`, managers + admins. This is
// the open-source policy resolver — the single seam a higher tier swaps to
// also consult a stored-membership table. Returns nil for a non-registered
// principal (anonymous / trigger have no role standing).
func (p Principal) GranteeSet() []uuid.UUID {
	if p.Kind != KindRegisteredUser || p.UserID == uuid.Nil {
		return nil
	}
	set := []uuid.UUID{p.UserID}
	switch p.TenantRole {
	case auth.RoleAdmin:
		set = append(set, GroupAdmin, GroupManager, GroupUser)
	case auth.RoleManager:
		set = append(set, GroupManager, GroupUser)
	default:
		set = append(set, GroupUser)
	}
	return set
}

// HasResourceCapability reports whether p holds capability on a resource owned
// by ownerPrincipalID and carrying grants. True if p (or a role-group in its
// grantee-set) owns the resource — owners hold view/bind/manage implicitly —
// or holds a grant carrying capability.
func (p Principal) HasResourceCapability(ownerPrincipalID uuid.UUID, grants []Grant, capability string) bool {
	set := p.GranteeSet()
	inSet := func(id uuid.UUID) bool {
		for _, g := range set {
			if g == id {
				return true
			}
		}
		return false
	}
	if inSet(ownerPrincipalID) {
		return true
	}
	for _, g := range grants {
		if !inSet(g.GranteeID) {
			continue
		}
		for _, c := range g.Capabilities {
			if c == capability {
				return true
			}
		}
	}
	return false
}
