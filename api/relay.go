package api

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const (
	relayCodeTTL      = 30 * time.Second
	relayCookieMaxAge = 900 // 15 min sliding window
	relayCookieName   = "__air_session"
	relayNonceTTL     = 15 * time.Minute
	relayNonceName    = "__Host-airlock_relay_nonce"
	relayDevNonceName = "__air_relay_nonce"
)

// relayHandler generates database-backed relay codes for cross-origin auth
// between the main domain and agent subdomains.
type relayHandler struct {
	db          *db.DB
	agentDomain string
	publicURL   string
	logger      *zap.Logger
}

// relayClaims are the identity and target values persisted for a relay code.
type relayClaims struct {
	UserID       string
	SessionID    string
	Email        string
	TenantRole   string
	AuthEpoch    int64
	AgentID      string
	TargetOrigin string
	ReturnPath   string
}

// --- Relay code generation (POST /auth/relay-code) ---

func (h *relayHandler) GenerateCode(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.GenerateRelayCodeRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	parsed, err := url.Parse(req.ReturnUrl)
	if err != nil || parsed.Host == "" {
		writeError(w, http.StatusBadRequest, "invalid returnUrl")
		return
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.User != nil {
		writeError(w, http.StatusBadRequest, "invalid returnUrl")
		return
	}
	slug, ok := agentSlugFromHost(parsed.Host, h.agentDomain)
	if !ok {
		writeError(w, http.StatusBadRequest, "returnUrl is not a valid agent subdomain")
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if claims.MustChangePassword {
		writeError(w, http.StatusForbidden, "password change required")
		return
	}
	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	agent, err := service.ResolveAgent(r.Context(), dbq.New(h.db.Pool()), slug)
	if err != nil {
		writeError(w, http.StatusBadRequest, "returnUrl is not a valid agent subdomain")
		return
	}

	targetOrigin, ok := canonicalRelayTargetOrigin(parsed, agent.Slug, h.agentDomain, h.publicURL)
	if !ok {
		writeError(w, http.StatusBadRequest, "returnUrl is not the canonical agent URL")
		return
	}
	returnPath := parsed.RequestURI()
	if !validRelayReturnPath(returnPath) {
		writeError(w, http.StatusBadRequest, "invalid returnUrl")
		return
	}
	if req.Nonce == "" {
		writeError(w, http.StatusBadRequest, "missing nonce")
		return
	}
	nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil || len(nonce) != 32 {
		writeError(w, http.StatusBadRequest, "invalid nonce")
		return
	}

	code, err := newRelaySecret()
	if err != nil {
		h.logger.Error("generate relay code", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to generate relay code")
		return
	}
	expiresAt := time.Now().Add(relayCodeTTL)
	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: pre-auth handoff state creation; the authenticated user and resolved target are persisted for one atomic callback exchange
	if err := q.CreateRelayCode(r.Context(), dbq.CreateRelayCodeParams{
		CodeHash:     hashToken(code),
		NonceHash:    hashToken(req.Nonce),
		UserID:       toPgUUID(uuid.MustParse(claims.Subject)),
		SessionID:    toPgUUID(sessionID),
		Email:        claims.Email,
		TenantRole:   claims.TenantRole,
		AuthEpoch:    claims.AuthEpoch,
		AgentID:      agent.ID,
		TargetOrigin: targetOrigin,
		ReturnPath:   returnPath,
		ExpiresAt:    pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}); err != nil {
		h.logger.Error("persist relay code", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to generate relay code")
		return
	}

	callbackURL := targetOrigin + "/__air/callback?code=" + url.QueryEscape(code) + "&return=" + url.QueryEscape(returnPath)

	writeProto(w, http.StatusOK, &airlockv1.GenerateRelayCodeResponse{
		Code:        code,
		CallbackUrl: callbackURL,
	})
}

func newRelaySecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// --- Cookie helpers ---

// issueSessionCookie creates a signed session JWT and sets it as an HttpOnly cookie.
func issueSessionCookie(w http.ResponseWriter, r *http.Request, jwtSecret string, targetAgentID uuid.UUID, c *relayClaims) error {
	uid, err := parseUUID(c.UserID)
	if err != nil {
		return fmt.Errorf("parse user ID: %w", err)
	}

	// Relay handoffs persist only the identity fields required by the
	// subdomain token, so these sessions carry id and email without a name.
	sessionID, err := parseUUID(c.SessionID)
	if err != nil {
		return fmt.Errorf("parse session ID: %w", err)
	}
	token, err := auth.IssueSubdomainToken(jwtSecret, targetAgentID, uid, sessionID, c.Email, "", c.TenantRole, c.AuthEpoch)
	if err != nil {
		return fmt.Errorf("issue session token: %w", err)
	}

	setSessionCookie(w, r, token)
	return nil
}

// setSessionCookie writes the __air_session cookie with sliding Max-Age.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     relayCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   relayCookieMaxAge,
		HttpOnly: true,
		Secure:   requestScheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

func setRelayNonceCookie(w http.ResponseWriter, r *http.Request, nonce string) {
	http.SetCookie(w, &http.Cookie{
		Name:     relayNonceCookieName(r),
		Value:    nonce,
		Path:     "/",
		MaxAge:   int(relayNonceTTL.Seconds()),
		HttpOnly: true,
		Secure:   requestScheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

func clearRelayNonceCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     relayNonceCookieName(r),
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   requestScheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

func relayNonceCookieName(r *http.Request) string {
	if requestScheme(r) == "https" {
		return relayNonceName
	}
	return relayDevNonceName
}

// --- Helpers ---

func validRelayReturnPath(returnPath string) bool {
	if !strings.HasPrefix(returnPath, "/") || strings.HasPrefix(returnPath, "//") {
		return false
	}
	parsed, err := url.Parse(returnPath)
	return err == nil && !parsed.IsAbs() && parsed.Host == ""
}

func canonicalRelayTargetOrigin(parsed *url.URL, slug, agentDomain, publicURL string) (string, bool) {
	public := configuredOriginURL(publicURL)
	expectedHost := strings.ToLower(slug + "." + strings.TrimSuffix(agentDomain, "."))
	if port := public.Port(); port != "" && !((public.Scheme == "https" && port == "443") || (public.Scheme == "http" && port == "80")) {
		expectedHost += ":" + port
	}
	if strings.ToLower(parsed.Host) != expectedHost {
		return "", false
	}
	if parsed.Scheme != public.Scheme && !(parsed.Scheme == "http" && isLocalhostName(parsed.Hostname())) {
		return "", false
	}
	return parsed.Scheme + "://" + expectedHost, true
}

func isLocalhostName(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}
