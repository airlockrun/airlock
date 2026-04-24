package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AgentClaims are the JWT claims for agent tokens.
type AgentClaims struct {
	jwt.RegisteredClaims
	AgentID string `json:"agent_id"`
}

// IssueAgentToken creates a signed JWT for an agent container (100-year expiry).
func IssueAgentToken(secret string, agentID uuid.UUID) (string, error) {
	now := time.Now()
	claims := AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   agentID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(100 * 365 * 24 * time.Hour)),
		},
		AgentID: agentID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateAgentToken validates a JWT and returns the agent claims.
// Rejects tokens that do not have an AgentID claim.
func ValidateAgentToken(secret, tokenString string) (*AgentClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AgentClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid agent token: %w", err)
	}
	claims, ok := token.Claims.(*AgentClaims)
	if !ok || claims.AgentID == "" {
		return nil, fmt.Errorf("invalid agent token: missing agent_id")
	}
	return claims, nil
}

// AgentMiddleware validates the agent JWT Bearer token and injects AgentClaims into context.
func AgentMiddleware(jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}
			token, ok := strings.CutPrefix(header, "Bearer ")
			if !ok || token == "" {
				http.Error(w, `{"error":"invalid authorization header"}`, http.StatusUnauthorized)
				return
			}

			claims, err := ValidateAgentToken(jwtSecret, token)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := withAgentClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AgentIDFromContext returns the agent UUID from context, set by AgentMiddleware.
func AgentIDFromContext(ctx interface{ Value(any) any }) uuid.UUID {
	claims, _ := ctx.Value(agentClaimsKey).(*AgentClaims)
	if claims == nil {
		return uuid.Nil
	}
	id, err := uuid.Parse(claims.AgentID)
	if err != nil {
		return uuid.Nil
	}
	return id
}
