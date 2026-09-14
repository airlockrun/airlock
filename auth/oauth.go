package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AdmitOAuthAccess validates the MCP profile, exact configured resource
// audience, live account epoch, client, and grant. OAuth carries no web session.
func AdmitOAuthAccess(ctx context.Context, q *dbq.Queries, secret, token, audience string) (*Claims, error) {
	claims, err := ValidateOAuthAccessToken(secret, token, audience)
	if err != nil {
		return nil, err
	}
	claims, err = ResolveLiveUserClaims(ctx, q, claims, false)
	if err != nil {
		return nil, err
	}
	if err := RequireSecuredAccount(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func verifyLiveOAuthGrant(ctx context.Context, q *dbq.Queries, claims *Claims, userID uuid.UUID) error {
	if len(claims.Audience) != 1 {
		return errors.New("invalid OAuth audience")
	}
	resource, err := url.Parse(claims.Audience[0])
	if err != nil || resource.Host == "" || resource.RawQuery != "" || resource.Fragment != "" || resource.User != nil || (resource.Scheme != "http" && resource.Scheme != "https") {
		return errors.New("invalid OAuth resource")
	}
	identifier := strings.TrimSuffix(strings.TrimPrefix(resource.Path, "/api/agent/"), "/mcp")
	agentID, err := uuid.Parse(identifier)
	if err != nil || agentID == uuid.Nil || resource.Path != "/api/agent/"+agentID.String()+"/mcp" {
		return errors.New("invalid OAuth target")
	}
	if _, err := q.GetOAuthClient(ctx, claims.ClientID); err != nil {
		return errors.New("inactive OAuth client")
	}
	grant, err := q.GetActiveGrant(ctx, dbq.GetActiveGrantParams{UserID: pgtype.UUID{Bytes: userID, Valid: true}, ClientID: claims.ClientID, AgentID: pgtype.UUID{Bytes: agentID, Valid: true}})
	if err != nil {
		return errors.New("inactive OAuth grant")
	}
	if !ScopeContains(claims.Scope, "mcp") || !ScopeContains(grant.Scope, "mcp") {
		return errors.New("insufficient OAuth scope")
	}
	return nil
}
