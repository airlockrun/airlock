package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/airlock/auth"
	"go.uber.org/zap"
)

const (
	relayCodeTTL    = 30 * time.Second
	relaySessionTTL = 7 * 24 * time.Hour // JWT inside cookie — long-lived
	relayCookieMaxAge = 900               // 15 min sliding window
	relayCookieName   = "__air_session"
)

// relayHandler generates and validates HMAC-signed relay codes for
// cross-origin auth between the main domain and agent subdomains.
type relayHandler struct {
	jwtSecret   string
	agentDomain string
	publicURL   string
	logger      *zap.Logger
}

// relayClaims are the claims embedded in a relay code.
type relayClaims struct {
	UserID       string
	Email        string
	TenantRole   string
	TargetOrigin string
	ExpiresAt    int64
}

// --- Relay code generation (POST /auth/relay-code) ---

type relayCodeRequest struct {
	ReturnURL string `json:"returnUrl"`
}

type relayCodeResponse struct {
	Code        string `json:"code"`
	CallbackURL string `json:"callbackUrl"`
}

func (h *relayHandler) GenerateCode(w http.ResponseWriter, r *http.Request) {
	var req relayCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	parsed, err := url.Parse(req.ReturnURL)
	if err != nil || parsed.Host == "" {
		writeError(w, http.StatusBadRequest, "invalid returnUrl")
		return
	}

	// Validate target is a subdomain of agentDomain.
	if !isAgentSubdomain(parsed.Host, h.agentDomain) {
		writeError(w, http.StatusBadRequest, "returnUrl is not a valid agent subdomain")
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	targetOrigin := parsed.Scheme + "://" + parsed.Host
	expiresAt := time.Now().Add(relayCodeTTL).Unix()

	code := signRelayCode(h.jwtSecret, relayClaims{
		UserID:       claims.Subject,
		Email:        claims.Email,
		TenantRole:   claims.TenantRole,
		TargetOrigin: targetOrigin,
		ExpiresAt:    expiresAt,
	})

	callbackURL := targetOrigin + "/__air/callback?code=" + url.QueryEscape(code) + "&return=" + url.QueryEscape(parsed.RequestURI())

	writeJSON(w, http.StatusOK, relayCodeResponse{
		Code:        code,
		CallbackURL: callbackURL,
	})
}

// --- Relay code signing and validation ---

// signRelayCode produces a base64url-encoded HMAC-signed relay code.
// Format: base64url(userID|email|role|targetOrigin|expiresUnix|hmacHex)
func signRelayCode(secret string, c relayClaims) string {
	payload := strings.Join([]string{
		c.UserID,
		c.Email,
		c.TenantRole,
		c.TargetOrigin,
		strconv.FormatInt(c.ExpiresAt, 10),
	}, "|")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := fmt.Sprintf("%x", mac.Sum(nil))

	return base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + sig))
}

// validateRelayCode parses and verifies a relay code.
func validateRelayCode(secret, code string) (*relayClaims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return nil, errors.New("invalid relay code encoding")
	}

	parts := strings.Split(string(raw), "|")
	if len(parts) != 6 {
		return nil, errors.New("invalid relay code format")
	}

	payload := strings.Join(parts[:5], "|")
	sig := parts[5]

	// Verify HMAC.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil, errors.New("invalid relay code signature")
	}

	// Check expiry.
	expiresAt, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return nil, errors.New("invalid relay code expiry")
	}
	if time.Now().Unix() > expiresAt {
		return nil, errors.New("relay code expired")
	}

	return &relayClaims{
		UserID:       parts[0],
		Email:        parts[1],
		TenantRole:   parts[2],
		TargetOrigin: parts[3],
		ExpiresAt:    expiresAt,
	}, nil
}

// --- Cookie helpers ---

// issueSessionCookie creates a signed session JWT and sets it as an HttpOnly cookie.
func issueSessionCookie(w http.ResponseWriter, r *http.Request, jwtSecret string, c *relayClaims) error {
	uid, err := parseUUID(c.UserID)
	if err != nil {
		return fmt.Errorf("parse user ID: %w", err)
	}

	token, err := auth.IssueTokenWithDuration(jwtSecret, uid, c.Email, c.TenantRole, relaySessionTTL)
	if err != nil {
		return fmt.Errorf("issue session token: %w", err)
	}

	setSessionCookie(w, r, token)
	return nil
}

// setSessionCookie writes the __air_session cookie with sliding Max-Age.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	secure := strings.HasPrefix(r.URL.Scheme, "https") || r.TLS != nil ||
		r.Header.Get("X-Forwarded-Proto") == "https"

	http.SetCookie(w, &http.Cookie{
		Name:     relayCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   relayCookieMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- Helpers ---

// isAgentSubdomain checks whether host is a subdomain of agentDomain.
// Strips port from host before comparing.
func isAgentSubdomain(host, agentDomain string) bool {
	// Strip port.
	if colon := strings.LastIndex(host, ":"); colon != -1 {
		host = host[:colon]
	}
	suffix := "." + agentDomain
	return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
}
