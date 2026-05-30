package api

import (
	"net/http"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/google/uuid"
)

// principalFromRequest builds the authz.Principal for an authenticated
// /api/v1 request from its JWT claims. /api/v1 sits behind the JWT
// middleware, so this is always a registered user; a malformed/absent
// claim yields a uuid.Nil principal, which authz.Authorize maps to 401.
func principalFromRequest(r *http.Request) authz.Principal {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		return authz.UserPrincipal(uuid.Nil, "")
	}
	return authz.UserPrincipal(auth.UserIDFromContext(r.Context()), auth.Role(claims.TenantRole))
}
