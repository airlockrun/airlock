package api

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SubdomainProxy wraps the main router and intercepts requests whose Host
// header matches {slug}.{agentDomain}. Matching requests are authenticated
// according to the route's access level and reverse-proxied to the agent's
// container. Non-matching requests fall through to inner.
func SubdomainProxy(agentDomain string, database *db.DB, s3 *storage.S3Client, dispatcher *trigger.Dispatcher, jwtSecret, publicURL string, logger *zap.Logger, inner http.Handler) http.Handler {
	if agentDomain == "" {
		panic("api: SubdomainProxy called with empty agentDomain")
	}

	suffix := "." + agentDomain

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip port from Host header (e.g. "foo.lvh.me:8080" → "foo.lvh.me").
		host := r.Host
		if colon := strings.LastIndex(host, ":"); colon != -1 {
			host = host[:colon]
		}

		// Check whether Host is a subdomain of agentDomain.
		if !strings.HasSuffix(host, suffix) {
			inner.ServeHTTP(w, r)
			return
		}

		slug := strings.TrimSuffix(host, suffix)
		if slug == "" {
			// Bare domain (no subdomain) → pass through.
			inner.ServeHTTP(w, r)
			return
		}

		// Reserved subdomains — not valid agent slugs.
		switch slug {
		case "api", "s3":
			inner.ServeHTTP(w, r)
			return
		}

		log := logger.With(zap.String("slug", slug), zap.String("path", r.URL.Path), zap.String("method", r.Method))

		// Auth relay callback — exchange relay code for session cookie.
		if r.URL.Path == "/__air/callback" {
			handleRelayCallback(w, r, jwtSecret, log)
			return
		}

		q := dbq.New(database.Pool())

		// Look up agent by slug.
		agent, err := q.GetAgentBySlug(r.Context(), slug)
		if err != nil {
			log.Warn("agent not found for slug", zap.Error(err))
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		agentID := pgUUID(agent.ID)

		// Public storage zone reads under the agent's subdomain. Intercepted
		// before route resolution so a builder's RegisterRoute("/__air/...")
		// can never claim this prefix. Only zones with read_access="public"
		// respond; others return 404 (same as the host-level fallback).
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/__air/storage/") {
			rest := strings.TrimPrefix(r.URL.Path, "/__air/storage/")
			zoneSlug, key, _ := strings.Cut(rest, "/")
			servePublicStorageZone(w, r, database, s3, agentID, zoneSlug, key, log)
			return
		}

		// Look up the registered route — match exact paths first, then parameterized patterns.
		routes, err := q.ListRoutesByAgentAndMethod(r.Context(), dbq.ListRoutesByAgentAndMethodParams{
			AgentID: agent.ID,
			Method:  r.Method,
		})
		if err != nil {
			log.Debug("no routes found", zap.Error(err))
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		route, ok := matchRoute(routes, r.URL.Path)
		if !ok {
			log.Debug("no route matched", zap.String("path", r.URL.Path))
			writeError(w, http.StatusNotFound, "route not found")
			return
		}

		// Enforce access control based on route.Access.
		var userID uuid.UUID
		var userEmail string

		switch route.Access {
		case "public":
			// No auth required.

		case "user":
			claims, ok := validateSubdomainAuth(r, jwtSecret)
			if !ok {
				rejectOrRedirect(w, r, publicURL)
				return
			}
			uid, err := uuid.Parse(claims.Subject)
			if err != nil {
				rejectOrRedirect(w, r, publicURL)
				return
			}
			hasAccess, err := q.HasAgentAccess(r.Context(), dbq.HasAgentAccessParams{
				AgentID: agent.ID,
				UserID:  toPgUUID(uid),
			})
			if err != nil || !hasAccess {
				log.Warn("user lacks agent access", zap.String("user_id", uid.String()), zap.Error(err))
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
			userID = uid
			userEmail = claims.Email

		case "admin":
			claims, ok := validateSubdomainAuth(r, jwtSecret)
			if !ok {
				rejectOrRedirect(w, r, publicURL)
				return
			}
			uid, err := uuid.Parse(claims.Subject)
			if err != nil {
				rejectOrRedirect(w, r, publicURL)
				return
			}
			member, err := q.GetAgentMember(r.Context(), dbq.GetAgentMemberParams{
				AgentID: agent.ID,
				UserID:  toPgUUID(uid),
			})
			if err != nil {
				log.Warn("user is not an agent member", zap.String("user_id", uid.String()), zap.Error(err))
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
			if !auth.RoleAtLeast(member.Role, "admin") {
				log.Warn("user is not agent admin", zap.String("user_id", uid.String()), zap.String("role", member.Role))
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
			userID = uid
			userEmail = claims.Email

		default:
			log.Error("unknown route access level", zap.String("access", route.Access))
			writeError(w, http.StatusInternalServerError, "misconfigured route")
			return
		}

		// Ensure agent container is running.
		ctr, err := dispatcher.EnsureRunning(r.Context(), agentID)
		if err != nil {
			log.Error("failed to start agent container", zap.Error(err))
			writeError(w, http.StatusBadGateway, "agent unavailable")
			return
		}

		// Build reverse proxy to the container endpoint.
		target, err := url.Parse(ctr.Endpoint)
		if err != nil {
			log.Error("invalid container endpoint", zap.String("endpoint", ctr.Endpoint), zap.Error(err))
			writeError(w, http.StatusBadGateway, "agent unavailable")
			return
		}

		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				// Keep the original path and query string.
				req.Host = target.Host

				// Authenticate to the container.
				req.Header.Set("Authorization", "Bearer "+ctr.Token)

				// Forward client IP to the agent container.
				req.Header.Set("X-Forwarded-For", r.RemoteAddr)
				req.Header.Set("X-Real-IP", r.RemoteAddr)

				// Pass identity headers for authenticated requests.
				if userID != uuid.Nil {
					req.Header.Set("X-User-ID", userID.String())
					req.Header.Set("X-User-Email", userEmail)
				}
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Error("proxy error", zap.Error(err))
				writeError(w, http.StatusBadGateway, "proxy error")
			},
		}

		// Sliding window: refresh session cookie on every successful proxied request.
		if cookie, err := r.Cookie(relayCookieName); err == nil {
			setSessionCookie(w, r, cookie.Value)
		}

		log.Debug("proxying request", zap.String("target", ctr.Endpoint))
		proxy.ServeHTTP(w, r)
	})
}

// matchRoute finds the best matching route for a request path.
// Exact matches take priority over parameterized patterns.
// Parameterized segments like {slug} match a single path segment.
func matchRoute(routes []dbq.AgentRoute, reqPath string) (dbq.AgentRoute, bool) {
	// First pass: exact match.
	for _, r := range routes {
		if r.Path == reqPath {
			return r, true
		}
	}

	// Second pass: pattern match ({param} segments).
	reqParts := strings.Split(reqPath, "/")
	for _, r := range routes {
		if !strings.Contains(r.Path, "{") {
			continue
		}
		routeParts := strings.Split(r.Path, "/")
		if len(routeParts) != len(reqParts) {
			continue
		}
		match := true
		for i := range routeParts {
			if strings.HasPrefix(routeParts[i], "{") && strings.HasSuffix(routeParts[i], "}") {
				continue // wildcard segment matches anything
			}
			if routeParts[i] != reqParts[i] {
				match = false
				break
			}
		}
		if match {
			return r, true
		}
	}

	return dbq.AgentRoute{}, false
}

// handleRelayCallback exchanges a relay code for a session cookie.
// GET /__air/callback?code=xxx&return=/path
func handleRelayCallback(w http.ResponseWriter, r *http.Request, jwtSecret string, log *zap.Logger) {
	code := r.URL.Query().Get("code")
	returnPath := r.URL.Query().Get("return")
	if code == "" || returnPath == "" {
		writeError(w, http.StatusBadRequest, "missing code or return parameter")
		return
	}

	claims, err := validateRelayCode(jwtSecret, code)
	if err != nil {
		log.Warn("relay code validation failed", zap.Error(err))
		writeError(w, http.StatusUnauthorized, "invalid or expired relay code")
		return
	}

	// Verify targetOrigin matches the current request host.
	requestOrigin := requestScheme(r) + "://" + r.Host
	if claims.TargetOrigin != requestOrigin {
		log.Warn("relay code target origin mismatch",
			zap.String("expected", claims.TargetOrigin),
			zap.String("actual", requestOrigin))
		writeError(w, http.StatusBadRequest, "origin mismatch")
		return
	}

	if err := issueSessionCookie(w, r, jwtSecret, claims); err != nil {
		log.Error("failed to issue session cookie", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "auth failed")
		return
	}

	http.Redirect(w, r, returnPath, http.StatusFound)
}

// validateSubdomainAuth tries Authorization header first, then session cookie.
func validateSubdomainAuth(r *http.Request, jwtSecret string) (*auth.Claims, bool) {
	// Try Bearer token (API clients).
	if claims, ok := validateBearerToken(r, jwtSecret); ok {
		return claims, true
	}
	// Try session cookie (browser clients).
	cookie, err := r.Cookie(relayCookieName)
	if err != nil {
		return nil, false
	}
	claims, err := auth.ValidateToken(jwtSecret, cookie.Value)
	if err != nil {
		return nil, false
	}
	return claims, true
}

// rejectOrRedirect returns 401 for API/htmx clients or redirects browsers to the relay page.
func rejectOrRedirect(w http.ResponseWriter, r *http.Request, publicURL string) {
	// htmx requests: return 401 so client-side handler can reload the page.
	if r.Header.Get("HX-Request") == "true" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// Full page navigation: redirect to auth relay.
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		currentURL := requestScheme(r) + "://" + r.Host + r.RequestURI
		relayURL := publicURL + "/auth/relay?return=" + url.QueryEscape(currentURL)
		http.Redirect(w, r, relayURL, http.StatusFound)
		return
	}
	// API clients: plain 401.
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

// validateBearerToken extracts and validates a JWT from the Authorization header.
func validateBearerToken(r *http.Request, jwtSecret string) (*auth.Claims, bool) {
	header := r.Header.Get("Authorization")
	if header == "" || !strings.HasPrefix(header, "Bearer ") {
		return nil, false
	}
	token := strings.TrimPrefix(header, "Bearer ")
	claims, err := auth.ValidateToken(jwtSecret, token)
	if err != nil {
		return nil, false
	}
	return claims, true
}

// requestScheme returns "https" or "http" based on the request.
func requestScheme(r *http.Request) string {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}
