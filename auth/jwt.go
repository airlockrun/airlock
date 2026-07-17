package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	AccessTokenDuration    = 15 * time.Minute
	RefreshTokenDuration   = 7 * 24 * time.Hour
	SubdomainTokenDuration = time.Hour

	userTokenIssuer      = "airlock/user"
	userTokenAudience    = "airlock-api"
	refreshTokenIssuer   = "airlock/refresh"
	refreshTokenAudience = "airlock-refresh"
	oauthTokenIssuer     = "airlock/oauth"
	agentTokenIssuer     = "airlock/agent"
	agentTokenAudience   = "airlock-agent-api"
	subdomainTokenIssuer = "airlock/subdomain"

	tokenUseUserAccess = "user_access"
	tokenUseRefresh    = "refresh"
	tokenUseOAuthMCP   = "oauth_mcp"
	tokenUseAgent      = "agent"
	tokenUseSubdomain  = "subdomain"
)

var ErrInvalidAudience = errors.New("invalid token audience")

// Claims are the JWT claims for Airlock tokens.
//
// ClientID and Scope are populated only on OAuth MCP access tokens. AgentID is
// populated only on subdomain tokens. TokenUse, issuer, and audience identify
// the token profile; validators require all three.
type Claims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
	// DisplayName is the user's display name, carried so proxied agent
	// requests can forward it (X-User-Name) without a DB lookup. Display
	// claim only — never used for authorization. Empty for OAuth/MCP tokens.
	DisplayName string           `json:"name,omitempty"`
	TenantRole  string           `json:"tenant_role"`
	ClientID    string           `json:"client_id,omitempty"`
	Scope       string           `json:"scope,omitempty"`
	AgentID     string           `json:"agent_id,omitempty"`
	TokenUse    string           `json:"token_use"`
	SessionID   string           `json:"sid,omitempty"`
	AuthEpoch   int64            `json:"auth_epoch"`
	AuthTime    *jwt.NumericDate `json:"auth_time,omitempty"`
	// MustChangePassword mirrors users.must_change_password. When true the
	// /api/v1 secured-account gate restricts the token to the account-securing
	// endpoints until the user sets a strong password or registers a passkey,
	// then receives a fresh token with the flag cleared. Web-login tokens carry
	// the live value at issue; OAuth/MCP tokens never set it.
	MustChangePassword bool `json:"must_change_password,omitempty"`
}

// IssueToken creates a signed access token (15 min).
func IssueToken(secret string, userID uuid.UUID, email, displayName, tenantRole string, mustChangePassword bool) (string, error) {
	return IssueUserAccessToken(secret, userID, email, displayName, tenantRole, mustChangePassword, uuid.New(), 0, time.Now())
}

// IssueUserAccessToken creates a session-bound first-party access token.
func IssueUserAccessToken(secret string, userID uuid.UUID, email, displayName, tenantRole string, mustChangePassword bool, sessionID uuid.UUID, authEpoch int64, authTime time.Time) (string, error) {
	return issueUserToken(secret, userID, email, displayName, tenantRole, mustChangePassword, sessionID, authEpoch, authTime, AccessTokenDuration, userTokenIssuer, userTokenAudience, tokenUseUserAccess)
}

// IssueRefreshToken creates a signed refresh token (7 days).
func IssueRefreshToken(secret string, userID uuid.UUID, email, displayName, tenantRole string, mustChangePassword bool) (string, error) {
	return issueUserToken(secret, userID, email, displayName, tenantRole, mustChangePassword, uuid.New(), 0, time.Now(), RefreshTokenDuration, refreshTokenIssuer, refreshTokenAudience, tokenUseRefresh)
}

func issueUserToken(secret string, userID uuid.UUID, email, displayName, tenantRole string, mustChangePassword bool, sessionID uuid.UUID, authEpoch int64, authTime time.Time, duration time.Duration, issuer, audience, tokenUse string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
		},
		Email:              email,
		DisplayName:        displayName,
		TenantRole:         tenantRole,
		TokenUse:           tokenUse,
		SessionID:          sessionID.String(),
		AuthEpoch:          authEpoch,
		AuthTime:           jwt.NewNumericDate(authTime),
		MustChangePassword: mustChangePassword,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// IssueOAuthAccessToken mints a JWT with the OAuth-side claims set
// (ClientID + Scope + Audience). 15-min lifetime, same HS256 secret
// as the web-login tokens.
//
// This is the sole issuer that sets ClientID. The OAuth validator requires it
// together with the OAuth issuer, token use, scope, and target audience.
//
// audience is the canonical resource URL, e.g.
// "https://airlock.example.com/api/agent/<uuid>/mcp". scope is the
// space-delimited scope string ("mcp" in v1).
func IssueOAuthAccessToken(secret string, userID uuid.UUID, email, tenantRole, clientID, scope, audience string, authEpoch int64) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    oauthTokenIssuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenDuration)),
		},
		Email:      email,
		TenantRole: tenantRole,
		ClientID:   clientID,
		Scope:      scope,
		TokenUse:   tokenUseOAuthMCP,
		AuthEpoch:  authEpoch,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// IssueSubdomainToken creates a short-lived user identity token bound to one
// agent subdomain.
func IssueSubdomainToken(secret string, targetAgentID, userID, sessionID uuid.UUID, email, displayName, tenantRole string, authEpoch int64) (string, error) {
	if sessionID == uuid.Nil {
		return "", errors.New("subdomain token session id is required")
	}
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    subdomainTokenIssuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{subdomainAudience(targetAgentID)},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(SubdomainTokenDuration)),
		},
		Email:       email,
		DisplayName: displayName,
		TenantRole:  tenantRole,
		AgentID:     targetAgentID.String(),
		TokenUse:    tokenUseSubdomain,
		SessionID:   sessionID.String(),
		AuthEpoch:   authEpoch,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateUserAccessToken accepts only first-party user access tokens.
func ValidateUserAccessToken(secret, tokenString string) (*Claims, error) {
	claims := &Claims{}
	if err := parseProfileToken(secret, tokenString, claims, userTokenIssuer, userTokenAudience); err != nil {
		return nil, fmt.Errorf("invalid user access token: %w", err)
	}
	if claims.TokenUse != tokenUseUserAccess || claims.ClientID != "" || claims.Scope != "" || claims.AgentID != "" {
		return nil, errors.New("invalid user access token profile")
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, errors.New("invalid user access token subject")
	}
	if _, err := uuid.Parse(claims.SessionID); err != nil || claims.AuthTime == nil || claims.AuthEpoch < 0 {
		return nil, errors.New("invalid user access token session claims")
	}
	return claims, nil
}

// ValidateRefreshToken accepts only signed refresh-profile tokens.
func ValidateRefreshToken(secret, tokenString string) (*Claims, error) {
	claims := &Claims{}
	if err := parseProfileToken(secret, tokenString, claims, refreshTokenIssuer, refreshTokenAudience); err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}
	if claims.TokenUse != tokenUseRefresh || claims.ClientID != "" || claims.Scope != "" || claims.AgentID != "" {
		return nil, errors.New("invalid refresh token profile")
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, errors.New("invalid refresh token subject")
	}
	return claims, nil
}

// ValidateOAuthAccessToken accepts only OAuth MCP tokens for audience.
func ValidateOAuthAccessToken(secret, tokenString, audience string) (*Claims, error) {
	claims := &Claims{}
	if err := parseIssuerToken(secret, tokenString, claims, oauthTokenIssuer); err != nil {
		return nil, fmt.Errorf("invalid OAuth access token: %w", err)
	}
	if claims.TokenUse != tokenUseOAuthMCP || claims.ClientID == "" || claims.Scope == "" || claims.AgentID != "" || claims.MustChangePassword {
		return nil, errors.New("invalid OAuth access token profile")
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, errors.New("invalid OAuth access token subject")
	}
	if err := requireExactAudience(claims, audience); err != nil {
		return nil, fmt.Errorf("invalid OAuth access token: %w", err)
	}
	return claims, nil
}

// ValidateSubdomainToken accepts only a subdomain token bound to targetAgentID.
func ValidateSubdomainToken(secret, tokenString string, targetAgentID uuid.UUID) (*Claims, error) {
	claims := &Claims{}
	if err := parseProfileToken(secret, tokenString, claims, subdomainTokenIssuer, subdomainAudience(targetAgentID)); err != nil {
		return nil, fmt.Errorf("invalid subdomain token: %w", err)
	}
	if claims.TokenUse != tokenUseSubdomain || claims.AgentID != targetAgentID.String() || claims.ClientID != "" || claims.Scope != "" || claims.MustChangePassword {
		return nil, errors.New("invalid subdomain token profile")
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, errors.New("invalid subdomain token subject")
	}
	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil || sessionID == uuid.Nil || claims.AuthEpoch < 0 {
		return nil, errors.New("invalid subdomain token session claims")
	}
	return claims, nil
}

func parseProfileToken(secret, tokenString string, claims jwt.Claims, issuer, audience string) error {
	if err := parseIssuerToken(secret, tokenString, claims, issuer); err != nil {
		return err
	}
	return requireExactAudience(claims, audience)
}

func parseIssuerToken(secret, tokenString string, claims jwt.Claims, issuer string) error {
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return err
	}
	registered, err := registeredClaims(claims)
	if err != nil {
		return err
	}
	if registered.IssuedAt == nil {
		return errors.New("token is missing issued-at claim")
	}
	return nil
}

func requireExactAudience(claims jwt.Claims, audience string) error {
	registered, err := registeredClaims(claims)
	if err != nil {
		return err
	}
	if len(registered.Audience) != 1 || registered.Audience[0] != audience {
		return ErrInvalidAudience
	}
	return nil
}

func registeredClaims(claims jwt.Claims) (*jwt.RegisteredClaims, error) {
	switch c := claims.(type) {
	case *Claims:
		return &c.RegisteredClaims, nil
	case *AgentClaims:
		return &c.RegisteredClaims, nil
	default:
		return nil, errors.New("invalid token claims")
	}
}

func subdomainAudience(agentID uuid.UUID) string {
	return "airlock-agent:" + agentID.String()
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
