package auth

import (
	"context"

	"github.com/google/uuid"
)

type contextKey int

const (
	claimsKey contextKey = iota
	agentClaimsKey
)

// withClaims stores claims in the context (used by middleware).
func withClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// withAgentClaims stores agent claims in the context (used by AgentMiddleware).
func withAgentClaims(ctx context.Context, claims *AgentClaims) context.Context {
	return context.WithValue(ctx, agentClaimsKey, claims)
}

// ClaimsFromContext retrieves the JWT claims from the context.
func ClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsKey).(*Claims)
	return claims
}

// UserIDFromContext returns the user ID from the JWT claims.
func UserIDFromContext(ctx context.Context) uuid.UUID {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return uuid.Nil
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil
	}
	return id
}
