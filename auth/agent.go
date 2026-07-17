package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	// AgentTokenDuration bounds exposure while leaving ample time for a run to
	// finish. Containers are proactively replaced before this window closes.
	AgentTokenDuration = 7 * 24 * time.Hour
	// AgentTokenRotationWindow is the minimum lifetime required when reusing a
	// running container.
	AgentTokenRotationWindow = 24 * time.Hour
	agentTokenProfile        = "agent-api/v1"
)

// AgentClaims are the JWT claims for agent tokens.
type AgentClaims struct {
	jwt.RegisteredClaims
	AgentID      string `json:"agent_id"`
	TokenUse     string `json:"token_use"`
	Profile      string `json:"profile"`
	TokenVersion int64  `json:"token_version"`
}

// IssueAgentToken creates a versioned JWT for an agent container.
func IssueAgentToken(secret string, agentID uuid.UUID, tokenVersion int64) (string, error) {
	if tokenVersion < 1 {
		return "", errors.New("agent token version must be positive")
	}
	now := time.Now()
	claims := AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    agentTokenIssuer,
			Subject:   agentID.String(),
			Audience:  jwt.ClaimStrings{agentTokenAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AgentTokenDuration)),
		},
		AgentID:      agentID.String(),
		TokenUse:     tokenUseAgent,
		Profile:      agentTokenProfile,
		TokenVersion: tokenVersion,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateAgentToken validates a JWT and returns the agent claims.
// Rejects tokens that do not have an AgentID claim.
func ValidateAgentToken(secret, tokenString string) (*AgentClaims, error) {
	claims := &AgentClaims{}
	if err := parseProfileToken(secret, tokenString, claims, agentTokenIssuer, agentTokenAudience); err != nil {
		return nil, fmt.Errorf("invalid agent token: %w", err)
	}
	if _, err := uuid.Parse(claims.AgentID); err != nil ||
		claims.TokenUse != tokenUseAgent ||
		claims.Profile != agentTokenProfile ||
		claims.TokenVersion < 1 ||
		claims.Subject != claims.AgentID {
		return nil, errors.New("invalid agent token profile")
	}
	return claims, nil
}

type agentTokenQuerier interface {
	GetAgentTokenAuth(context.Context, pgtype.UUID) (dbq.GetAgentTokenAuthRow, error)
}

// AgentMiddleware validates the agent JWT and its live database state on every
// request, then injects AgentClaims into context.
func AgentMiddleware(jwtSecret string, q agentTokenQuerier) func(http.Handler) http.Handler {
	if q == nil {
		panic("auth: agent token querier is required")
	}
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
			agentID := uuid.MustParse(claims.AgentID)
			state, err := q.GetAgentTokenAuth(r.Context(), pgtype.UUID{Bytes: agentID, Valid: true})
			if err != nil || (state.Status != "active" && state.Status != "building") || state.AgentTokenVersion != claims.TokenVersion {
				http.Error(w, `{"error":"agent token revoked"}`, http.StatusUnauthorized)
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
