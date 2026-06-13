package auth

import (
	"net/http"
)

// Role is a tenant role — what a user can do in Airlock as a platform,
// independent of any per-agent access. Mirrors agentsdk.Access (the
// per-agent axis) so the two gates read the same way.
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleUser    Role = "user"
)

// roleLevel maps tenant roles to their hierarchy level.
// Higher level = more privileges. admin > manager > user.
var roleLevel = map[Role]int{
	RoleAdmin:   3,
	RoleManager: 2,
	RoleUser:    1,
}

// AtLeast reports whether r ranks at or above min. An unknown role
// (including the empty string) ranks below everything.
func (r Role) AtLeast(min Role) bool {
	return roleLevel[r] >= roleLevel[min]
}

// RequireTenantRole returns middleware that checks the user has at least the given role.
// Uses hierarchy: admin > manager > user. Returns 403 if not authorized.
func RequireTenantRole(minRole Role) func(http.Handler) http.Handler {
	if roleLevel[minRole] == 0 {
		panic("auth: unknown role " + string(minRole))
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if !Role(claims.TenantRole).AtLeast(minRole) {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
