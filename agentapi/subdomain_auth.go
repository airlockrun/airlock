package agentapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/airlockrun/airlock/auth"
)

// rejectOrRedirect returns 401 for API/htmx clients or redirects
// browsers to the relay page. The relay endpoint (in api/relay.go)
// then returns the user to currentURL with a fresh session cookie.
func rejectOrRedirect(w http.ResponseWriter, r *http.Request, publicURL string) {
	if r.Header.Get("HX-Request") == "true" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		currentURL := auth.RequestScheme(r) + "://" + r.Host + r.RequestURI
		relayURL := publicURL + "/auth/relay?return=" + url.QueryEscape(currentURL)
		http.Redirect(w, r, relayURL, http.StatusFound)
		return
	}
	writeError(w, http.StatusUnauthorized, "unauthorized")
}
