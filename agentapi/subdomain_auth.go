package agentapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

// relayCookieName must match api/relay.go's session-cookie name —
// this is the cookie a browser carries after the relay handshake.
// Defined here as well so the subdomain-storage path can validate
// session cookies without a cross-package call (api/relay sets it;
// agentapi/storage reads it; both reference the same name).
const relayCookieName = "__air_session"

// validateSubdomainAuth tries the Authorization header first, then
// the relay session cookie. The api/proxy.go entry point and the
// agentapi/storage.go internal helpers both call it.
func validateSubdomainAuth(r *http.Request, q *dbq.Queries, jwtSecret string, targetAgentID uuid.UUID) (*auth.Claims, bool) {
	if r.Header.Get("Authorization") != "" {
		return validateBearerToken(r, q, jwtSecret)
	}
	cookie, err := r.Cookie(relayCookieName)
	if err != nil {
		return nil, false
	}
	claims, err := auth.ValidateSubdomainToken(jwtSecret, cookie.Value, targetAgentID)
	if err != nil {
		return nil, false
	}
	claims, err = auth.ResolveLiveUserClaims(r.Context(), q, claims, true)
	if err != nil || claims.MustChangePassword {
		return nil, false
	}
	return claims, true
}

// rejectOrRedirect returns 401 for API/htmx clients or redirects
// browsers to the relay page. The relay endpoint (in api/relay.go)
// then returns the user to currentURL with a fresh session cookie.
func rejectOrRedirect(w http.ResponseWriter, r *http.Request, publicURL string) {
	if r.Header.Get("HX-Request") == "true" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		currentURL := requestScheme(r) + "://" + r.Host + r.RequestURI
		relayURL := publicURL + "/auth/relay?return=" + url.QueryEscape(currentURL)
		http.Redirect(w, r, relayURL, http.StatusFound)
		return
	}
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

func validateBearerToken(r *http.Request, q *dbq.Queries, jwtSecret string) (*auth.Claims, bool) {
	header := r.Header.Get("Authorization")
	if header == "" || !strings.HasPrefix(header, "Bearer ") {
		return nil, false
	}
	token := strings.TrimPrefix(header, "Bearer ")
	claims, err := auth.ValidateUserAccessToken(jwtSecret, token)
	if err != nil {
		return nil, false
	}
	claims, err = auth.ResolveLiveUserClaims(r.Context(), q, claims, true)
	if err != nil || claims.MustChangePassword {
		return nil, false
	}
	return claims, true
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}
