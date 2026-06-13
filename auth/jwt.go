package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	AccessTokenDuration  = 15 * time.Minute
	RefreshTokenDuration = 7 * 24 * time.Hour
)

// Claims are the JWT claims for Airlock tokens.
//
// ClientID and Scope are populated ONLY by IssueOAuthAccessToken (the
// MCP server-side OAuth flow). Web-login tokens never carry them — the
// presence of ClientID is the discriminator the MCP endpoint uses to
// branch between "OAuth access token, verify aud+scope+client" and
// "web-login JWT, accept as-is". Anything else in this codebase that
// sets ClientID would break that discrimination — see the
// Test_UserJWTHasNoClientID invariant in jwt_test.go.
//
// Audience comes from jwt.RegisteredClaims and binds an OAuth access
// token to a specific agent's MCP URL (RFC 8707 resource indicators).
type Claims struct {
	jwt.RegisteredClaims
	Email      string `json:"email"`
	TenantRole string `json:"tenant_role"`
	ClientID   string `json:"client_id,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

// IssueToken creates a signed access token (15 min).
func IssueToken(secret string, userID uuid.UUID, email, tenantRole string) (string, error) {
	return issueToken(secret, userID, email, tenantRole, AccessTokenDuration)
}

// IssueRefreshToken creates a signed refresh token (7 days).
func IssueRefreshToken(secret string, userID uuid.UUID, email, tenantRole string) (string, error) {
	return issueToken(secret, userID, email, tenantRole, RefreshTokenDuration)
}

// IssueTokenWithDuration creates a signed token with a custom duration.
func IssueTokenWithDuration(secret string, userID uuid.UUID, email, tenantRole string, duration time.Duration) (string, error) {
	return issueToken(secret, userID, email, tenantRole, duration)
}

func issueToken(secret string, userID uuid.UUID, email, tenantRole string, duration time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
		},
		Email:      email,
		TenantRole: tenantRole,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// IssueOAuthAccessToken mints a JWT with the OAuth-side claims set
// (ClientID + Scope + Audience). 15-min lifetime, same HS256 secret
// as the web-login tokens.
//
// This is the SOLE call site in the codebase that sets ClientID.
// Anything else producing a JWT must not — the MCP endpoint uses
// ClientID's presence to decide whether the audience check should
// run. The web-login IssueToken / IssueTokenWithDuration paths
// deliberately keep ClientID empty.
//
// audience is the canonical resource URL, e.g.
// "https://airlock.example.com/api/agent/<uuid>/mcp". scope is the
// space-delimited scope string ("mcp" in v1).
func IssueOAuthAccessToken(secret string, userID uuid.UUID, email, tenantRole, clientID, scope, audience string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenDuration)),
		},
		Email:      email,
		TenantRole: tenantRole,
		ClientID:   clientID,
		Scope:      scope,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateToken validates a JWT and returns the claims.
func ValidateToken(secret, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// AudienceContains reports whether `target` is one of the audience
// values in the claim. Helper for the MCP endpoint's audience check.
func AudienceContains(aud jwt.ClaimStrings, target string) bool {
	for _, a := range aud {
		if a == target {
			return true
		}
	}
	return false
}

// ScopeContains reports whether `required` is present in a
// space-delimited scope string. OAuth 2.0 scopes are case-sensitive
// (RFC 6749 §3.3); we match exactly.
func ScopeContains(scope, required string) bool {
	if scope == "" || required == "" {
		return false
	}
	for _, s := range splitScope(scope) {
		if s == required {
			return true
		}
	}
	return false
}

// splitScope tokenizes on ASCII space — matches RFC 6749 §3.3 grammar.
func splitScope(scope string) []string {
	out := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(scope); i++ {
		if scope[i] == ' ' {
			if i > start {
				out = append(out, scope[start:i])
			}
			start = i + 1
		}
	}
	if start < len(scope) {
		out = append(out, scope[start:])
	}
	return out
}
