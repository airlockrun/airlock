package auth

import (
	"net/http"
)

// roleLevel maps tenant roles to their hierarchy level.
// Higher level = more privileges. admin > manager > user.
var roleLevel = map[string]int{
	"admin":   3,
	"manager": 2,
	"user":    1,
}

// RoleAtLeast returns true if the user's role is >= the minimum required role.
func RoleAtLeast(userRole, minRole string) bool {
	return roleLevel[userRole] >= roleLevel[minRole]
}

// RequireTenantRole returns middleware that checks the user has at least the given role.
// Uses hierarchy: admin > manager > user. Returns 403 if not authorized.
func RequireTenantRole(minRole string) func(http.Handler) http.Handler {
	if roleLevel[minRole] == 0 {
		panic("auth: unknown role " + minRole)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if !RoleAtLeast(claims.TenantRole, minRole) {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
