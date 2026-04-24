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
type Claims struct {
	jwt.RegisteredClaims
	Email      string `json:"email"`
	TenantRole string `json:"tenant_role"`
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
