package api

import (
	"net/http"

	"github.com/airlockrun/airlock/auth"
)

// securedAccountAllowlist is the set of "METHOD /path" entries a user flagged
// must_change_password may still reach: the account-securing endpoints plus the
// self profile read. Everything else under /api/v1 is blocked until they set a
// strong password or register a passkey.
var securedAccountAllowlist = map[string]bool{
	"GET /api/v1/me":                           true,
	"POST /api/v1/me/password":                 true,
	"POST /api/v1/me/passkeys/register/begin":  true,
	"POST /api/v1/me/passkeys/register/finish": true,
}

// securedAccountGate blocks a must_change_password principal from the rest of
// the API until the account is secured. It runs after auth.Middleware, so the
// claims are present. The flag is cleared by setting a password or registering a
// passkey; the SPA then calls /auth/refresh (which re-reads the live flag) and
// the gate releases. /auth/* (login, refresh, change-password) sits outside the
// /api/v1 group this wraps, so it stays reachable.
func securedAccountGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := auth.ClaimsFromContext(r.Context())
		if claims == nil || !claims.MustChangePassword {
			next.ServeHTTP(w, r)
			return
		}
		if securedAccountAllowlist[r.Method+" "+r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusForbidden, "password_change_required")
	})
}
