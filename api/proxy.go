package api

import (
	"crypto/hmac"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/agentapi"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	agentstoragesvc "github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// SubdomainProxy wraps the main router and intercepts requests whose Host
// header matches {slug}.{agentDomain}. Matching requests are authenticated
// according to the route's access level and reverse-proxied to the agent's
// container. Non-matching requests fall through to inner.
//
// bridgeMgr is required for the Telegram Web App auto-auth flow: the
// /__air/tg/auth intercept verifies initData against the bridge's bot
// token, which bridgeMgr decrypts on demand.
func SubdomainProxy(agentDomain string, database *db.DB, s3 *storage.S3Client, files *agentstoragesvc.Service, dispatcher *trigger.Dispatcher, bridgeMgr *trigger.BridgeManager, jwtSecret, publicURL string, inner http.Handler) http.Handler {
	if agentDomain == "" {
		panic("api: SubdomainProxy called with empty agentDomain")
	}
	if bridgeMgr == nil {
		panic("api: SubdomainProxy called with nil bridgeMgr")
	}
	if files == nil {
		panic("api: SubdomainProxy called with nil file service")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug, ok := agentSlugFromHost(r.Host, agentDomain)
		if !ok {
			inner.ServeHTTP(w, r)
			return
		}

		log := logFor(r).Named("proxy").With(zap.String("slug", slug))

		q := dbq.New(database.Pool())

		agent, err := service.ResolveAgent(r.Context(), q, slug)
		if err != nil {
			log.Warn("agent not found for slug", zap.Error(err))
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		agentID := pgUUID(agent.ID)
		if r.URL.Path == "/__air/callback" {
			handleRelayCallback(w, r, database, jwtSecret, agentID, log)
			return
		}

		// Telegram Web App auto-auth intercepts. /start serves the
		// bootstrap stub the menu button opens; /auth verifies initData
		// and issues an __air_session cookie. Same subdomain as the
		// agent's own routes, so the cookie is host-scoped to that
		// agent and can never reach the admin host or another agent.
		if pathIsTGWebApp(r.URL.Path) {
			if r.URL.Path == "/__air/tg/start" {
				handleTGWebAppStart(w, r, publicURL)
				return
			}
			handleTGWebAppAuth(r.Context(), w, r, jwtSecret, agentID, bridgeMgr, database, log)
			return
		}

		// Directory reads under the agent's subdomain. Intercepted before
		// route resolution so a builder's RegisterRoute("/__air/...")
		// can never claim this prefix. Auth check matches the directory's
		// read_access — public serves unauth, user/admin require subdomain
		// session cookie (rejectOrRedirect on miss kicks off login flow).
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/__air/storage/") {
			path := strings.TrimPrefix(r.URL.Path, "/__air/storage")
			agentapi.ServeStoragePath(w, r, database, s3, files, agentID, path, jwtSecret, publicURL, log)
			return
		}

		// Bundled framework assets (htmx, pico.css) — agentsdk registers
		// these inside its own mux at GET /__air/assets/{name}, so they
		// don't appear in agent_routes. Skip the route-table lookup and
		// per-route auth; forward straight to the container as public.
		// The agent's handler validates the filename against a closed
		// set so unknown names produce a 404 from the agent.
		isAssetGET := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/__air/assets/")

		var userID uuid.UUID
		var userEmail string
		var userDisplayName string
		callerAccess := agentsdk.AccessPublic
		cookieAuthenticated := false

		if isAssetGET {
			if claims, ok, fromCookie := validateSubdomainAuth(r, q, jwtSecret, agentID); ok {
				cookieAuthenticated = fromCookie
				uid, err := uuid.Parse(claims.Subject)
				if err == nil {
					p := authz.UserPrincipal(uid, auth.Role(claims.TenantRole))
					callerAccess = p.EffectiveAgentAccess(r.Context(), q, agentID)
					userID = uid
					userEmail = claims.Email
					userDisplayName = claims.DisplayName
				}
			}
			if !agent.AllowPublicRoutes && !authz.AccessAtLeast(callerAccess, agentsdk.AccessUser) {
				rejectOrRedirect(w, r, publicURL)
				return
			}
		} else {
			// Build the same ServeMux pattern set used by the agent before
			// selecting the route whose access policy applies.
			// airlockvet:allow-dbq reason: pure routing-table plumbing; authorization happens below per route.Access
			routes, err := q.ListRoutesByAgent(r.Context(), agent.ID)
			if err != nil {
				log.Debug("no routes found", zap.Error(err))
				writeError(w, http.StatusNotFound, "route not found")
				return
			}
			route, ok, err := matchRoute(routes, r)
			if err != nil {
				log.Error("invalid or ambiguous route table", zap.Error(err))
				writeError(w, http.StatusInternalServerError, "misconfigured routes")
				return
			}
			if !ok {
				log.Debug("no route matched")
				writeError(w, http.StatusNotFound, "route not found")
				return
			}

			// Enforce access control based on route.Access.
			switch route.Access {
			case "public":
				// Preserve optional authenticated identity on public routes so
				if claims, ok, fromCookie := validateSubdomainAuth(r, q, jwtSecret, agentID); ok {
					cookieAuthenticated = fromCookie
					uid, err := uuid.Parse(claims.Subject)
					if err == nil {
						p := authz.UserPrincipal(uid, auth.Role(claims.TenantRole))
						callerAccess = p.EffectiveAgentAccess(r.Context(), q, agentID)
						userID = uid
						userEmail = claims.Email
						userDisplayName = claims.DisplayName
					}
				}
				// The toggle closes only the anonymous public-route surface.
				// Authenticated app members still need public-tier assets and
				// endpoints used by their user/admin pages.
				if !agent.AllowPublicRoutes && !authz.AccessAtLeast(callerAccess, agentsdk.AccessUser) {
					rejectOrRedirect(w, r, publicURL)
					return
				}

			case "user", "admin":
				claims, ok, fromCookie := validateSubdomainAuth(r, q, jwtSecret, agentID)
				if !ok {
					rejectOrRedirect(w, r, publicURL)
					return
				}
				cookieAuthenticated = fromCookie
				uid, err := uuid.Parse(claims.Subject)
				if err != nil {
					rejectOrRedirect(w, r, publicURL)
					return
				}
				required := agentsdk.AccessUser
				if route.Access == "admin" {
					required = agentsdk.AccessAdmin
				}
				p := authz.UserPrincipal(uid, auth.Role(claims.TenantRole))
				callerAccess = p.EffectiveAgentAccess(r.Context(), q, agentID)
				if !authz.AccessAtLeast(callerAccess, required) {
					log.Warn("user lacks required agent access", zap.String("user_id", uid.String()), zap.String("required", string(required)))
					writeError(w, http.StatusForbidden, "forbidden")
					return
				}
				userID = uid
				userEmail = claims.Email
				userDisplayName = claims.DisplayName

			default:
				log.Error("unknown route access level", zap.String("access", route.Access))
				writeError(w, http.StatusInternalServerError, "misconfigured route")
				return
			}
		}
		if cookieAuthenticated && unsafeMethod(r.Method) && r.Header.Get("Origin") != requestOrigin(r) {
			writeError(w, http.StatusForbidden, "origin mismatch")
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
			Rewrite: func(req *httputil.ProxyRequest) {
				// Rewrite runs after Go strips inbound hop-by-hop headers, so a
				// client cannot nominate trusted headers in Connection and have
				// them removed after Airlock sets their authoritative values.
				req.SetURL(target)
				req.Out.Host = target.Host
				req.SetXForwarded()

				// Authenticate to the container.
				req.Out.Header.Set("Authorization", "Bearer "+ctr.Token)
				stripReservedAuthCookies(req.Out.Header)

				// Forward client IP to the agent container.
				req.Out.Header.Set("X-Real-IP", r.RemoteAddr)

				// Replace caller-controlled identity and access headers with
				// values established by Airlock.
				req.Out.Header.Del("X-User-ID")
				req.Out.Header.Del("X-User-Email")
				req.Out.Header.Del("X-User-Name")
				req.Out.Header.Set("X-Caller-Access", string(callerAccess))
				if userID != uuid.Nil {
					req.Out.Header.Set("X-User-ID", userID.String())
					req.Out.Header.Set("X-User-Email", userEmail)
					if userDisplayName != "" {
						req.Out.Header.Set("X-User-Name", userDisplayName)
					}
				}
			},
			ModifyResponse: func(resp *http.Response) error {
				stripReservedSetCookies(resp.Header)
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Error("proxy error", zap.Error(err))
				writeError(w, http.StatusBadGateway, "proxy error")
			},
		}

		// Sliding window: refresh session cookie on every successful proxied request.
		if cookieAuthenticated {
			cookie, err := r.Cookie(relayCookieName)
			if err == nil {
				setSessionCookie(w, r, cookie.Value)
			}
		}

		log.Debug("proxying request", zap.String("target", ctr.Endpoint))
		proxy.ServeHTTP(w, r)
	})
}

// matchRoute delegates parsing, precedence, HEAD-to-GET behavior, and wildcard
// semantics to the same net/http ServeMux implementation used by the agent.
func matchRoute(routes []dbq.AgentRoute, req *http.Request) (selected dbq.AgentRoute, ok bool, err error) {
	mux := http.NewServeMux()
	byPattern := make(map[string]dbq.AgentRoute, len(routes))
	defer func() {
		if recovered := recover(); recovered != nil {
			selected = dbq.AgentRoute{}
			ok = false
			err = fmt.Errorf("register route pattern: %v", recovered)
		}
	}()
	for _, route := range routes {
		pattern := route.Method + " " + route.Path
		mux.HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {})
		byPattern[pattern] = route
	}
	_, pattern := mux.Handler(req)
	selected, ok = byPattern[pattern]
	return selected, ok, nil
}

// handleRelayCallback exchanges a relay code for a session cookie.
// GET /__air/callback?code=xxx&return=/path
func handleRelayCallback(w http.ResponseWriter, r *http.Request, database *db.DB, jwtSecret string, targetAgentID uuid.UUID, log *zap.Logger) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	code := r.URL.Query().Get("code")
	returnPath := r.URL.Query().Get("return")
	if code == "" || returnPath == "" {
		writeError(w, http.StatusBadRequest, "missing code or return parameter")
		return
	}
	if !validRelayReturnPath(returnPath) {
		writeError(w, http.StatusBadRequest, "invalid return parameter")
		return
	}
	clearRelayNonceCookie(w, r)

	// airlockvet:allow-dbq reason: callback authentication is an opaque, one-time DB exchange; DELETE RETURNING is the authorization gate
	row, err := dbq.New(database.Pool()).ConsumeRelayCode(r.Context(), hashToken(code))
	if err != nil {
		log.Warn("relay code consumption failed", zap.Error(err))
		writeError(w, http.StatusUnauthorized, "invalid or expired relay code")
		return
	}
	nonce, err := r.Cookie(relayNonceCookieName(r))
	if err != nil || nonce.Value == "" {
		writeError(w, http.StatusUnauthorized, "invalid or expired relay code")
		return
	}
	if !hmac.Equal(row.NonceHash, hashToken(nonce.Value)) {
		writeError(w, http.StatusUnauthorized, "invalid or expired relay code")
		return
	}
	live, err := auth.ResolveLiveUserClaims(r.Context(), dbq.New(database.Pool()), &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: pgUUID(row.UserID).String()},
		SessionID:        pgUUID(row.SessionID).String(),
		AuthEpoch:        row.AuthEpoch,
	}, true)
	if err != nil || live.MustChangePassword {
		writeError(w, http.StatusUnauthorized, "invalid or expired relay code")
		return
	}
	claims := &relayClaims{
		UserID:       pgUUID(row.UserID).String(),
		SessionID:    pgUUID(row.SessionID).String(),
		Email:        live.Email,
		TenantRole:   live.TenantRole,
		AuthEpoch:    row.AuthEpoch,
		AgentID:      pgUUID(row.AgentID).String(),
		TargetOrigin: row.TargetOrigin,
		ReturnPath:   row.ReturnPath,
	}

	// Verify targetOrigin matches the current request host.
	actualOrigin := requestOrigin(r)
	if claims.TargetOrigin != actualOrigin {
		log.Warn("relay code target origin mismatch",
			zap.String("expected", claims.TargetOrigin),
			zap.String("actual", actualOrigin))
		writeError(w, http.StatusBadRequest, "origin mismatch")
		return
	}
	if claims.ReturnPath != returnPath {
		writeError(w, http.StatusBadRequest, "return mismatch")
		return
	}
	if claims.AgentID != targetAgentID.String() {
		log.Warn("relay code target agent mismatch",
			zap.String("expected", claims.AgentID),
			zap.String("actual", targetAgentID.String()))
		writeError(w, http.StatusBadRequest, "agent mismatch")
		return
	}

	if err := issueSessionCookie(w, r, jwtSecret, targetAgentID, claims); err != nil {
		log.Error("failed to issue session cookie", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "auth failed")
		return
	}

	http.Redirect(w, r, returnPath, http.StatusFound)
}

// validateSubdomainAuth accepts an explicit user bearer or an agent-bound
// session cookie. An explicit Authorization header never falls back to a
// cookie.
func validateSubdomainAuth(r *http.Request, q *dbq.Queries, jwtSecret string, targetAgentID uuid.UUID) (*auth.Claims, bool, bool) {
	if r.Header.Get("Authorization") != "" {
		claims, ok := validateBearerToken(r, q, jwtSecret)
		return claims, ok, false
	}
	// Try session cookie (browser clients).
	cookie, err := r.Cookie(relayCookieName)
	if err != nil {
		return nil, false, false
	}
	claims, err := auth.ValidateSubdomainToken(jwtSecret, cookie.Value, targetAgentID)
	if err != nil {
		return nil, false, false
	}
	claims, err = auth.ResolveLiveUserClaims(r.Context(), q, claims, true)
	if err != nil || claims.MustChangePassword {
		return nil, false, false
	}
	return claims, true, true
}

// rejectOrRedirect returns 401 for API/htmx clients or serves a stub
// HTML page for browsers. The stub picks at runtime: if it loads inside
// Telegram (window.Telegram.WebApp.initData present), it exchanges the
// initData for a session cookie via /__air/tg/auth; otherwise it
// redirects to the main-domain auth relay. One unauthenticated
// landing page covers both flows.
func rejectOrRedirect(w http.ResponseWriter, r *http.Request, publicURL string) {
	// htmx requests: return 401 so the layout's responseError handler
	// can reload the page — the reload picks up this same stub HTML and
	// the JS resolves auth (TG or relay) without a manual login step.
	if r.Header.Get("HX-Request") == "true" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		renderTGWebAppStub(w, r, publicURL)
		return
	}
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

// validateBearerToken extracts and validates a JWT from the Authorization header.
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

func agentSlugFromHost(host, agentDomain string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = strings.TrimSuffix(h, ".")
	} else if strings.Contains(host, ":") {
		return "", false
	}
	domain := strings.ToLower(strings.TrimSuffix(agentDomain, "."))
	if domain == "" || strings.Contains(domain, ":") {
		return "", false
	}
	slug, ok := strings.CutSuffix(host, "."+domain)
	if !ok || slug == "" || strings.Contains(slug, ".") {
		return "", false
	}
	switch slug {
	case "api", "s3":
		return "", false
	}
	return slug, true
}

func stripReservedAuthCookies(header http.Header) {
	values := header.Values("Cookie")
	if len(values) == 0 {
		return
	}
	header.Del("Cookie")
	kept := make([]string, 0)
	for _, value := range values {
		for part := range strings.SplitSeq(value, ";") {
			part = strings.TrimSpace(part)
			name, _, ok := strings.Cut(part, "=")
			if part == "" || ok && reservedAuthCookie(name) {
				continue
			}
			kept = append(kept, part)
		}
	}
	if len(kept) != 0 {
		header.Set("Cookie", strings.Join(kept, "; "))
	}
}

func stripReservedSetCookies(header http.Header) {
	values := header.Values("Set-Cookie")
	header.Del("Set-Cookie")
	for _, value := range values {
		name, _, ok := strings.Cut(value, "=")
		if ok && reservedAuthCookie(strings.TrimSpace(name)) {
			continue
		}
		header.Add("Set-Cookie", value)
	}
}

func reservedAuthCookie(name string) bool {
	return name == relayCookieName || name == relayNonceName || name == relayDevNonceName || name == accessCookieName || name == refreshCookieName
}

func unsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions && method != http.MethodTrace
}

func requestOrigin(r *http.Request) string {
	return requestScheme(r) + "://" + strings.ToLower(r.Host)
}

// requestScheme returns "https" or "http" based on the request.
func requestScheme(r *http.Request) string {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return "https"
	}
	return "http"
}
