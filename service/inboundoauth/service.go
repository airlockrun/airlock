// Package inboundoauth owns external-client entitlement and authenticated grant
// management. Token exchanges prove identity from opaque credentials, not UUIDs.
package inboundoauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"slices"
	"strings"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Entitle requires a real app grant, including an explicit public-level grant.
// The ungranted public floor cannot authorize consent or a token exchange.
func Entitle(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID) error {
	if err := authz.Authorize(ctx, q, p, authz.OAuthAccess, agentID); err != nil {
		return err
	}
	agent, err := q.GetAgentByID(ctx, pg(agentID))
	if err != nil {
		return err
	}
	if !agent.McpEnabled {
		return service.ErrForbidden
	}
	_, granted, err := p.EffectiveAgentAccessChecked(ctx, q, agentID)
	if err != nil {
		return err
	}
	if !granted {
		return service.ErrForbidden
	}
	return nil
}

// ConsumeCode verifies and consumes the code within the caller's exchange
// transaction. Invalid proofs must roll back that transaction.
func ConsumeCode(ctx context.Context, q *dbq.Queries, code, clientID, redirectURI, verifier string) (dbq.OauthAuthzCode, dbq.User, error) {
	if len(verifier) < 43 || len(verifier) > 128 {
		return dbq.OauthAuthzCode{}, dbq.User{}, service.ErrInvalidInput
	}
	for _, c := range verifier {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-._~", c) {
			continue
		}
		return dbq.OauthAuthzCode{}, dbq.User{}, service.ErrInvalidInput
	}
	client, err := q.GetOAuthClient(ctx, clientID)
	if err != nil {
		return dbq.OauthAuthzCode{}, dbq.User{}, err
	}
	if client.TokenEndpointAuthMethod != "none" || !slices.Contains(client.GrantTypes, "authorization_code") || !slices.Contains(client.ResponseTypes, "code") || !auth.ScopeContains(client.Scope, "mcp") {
		return dbq.OauthAuthzCode{}, dbq.User{}, service.ErrUnauthorized
	}
	row, err := q.ConsumeAuthzCode(ctx, code)
	if err != nil {
		return row, dbq.User{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if row.ClientID != clientID || row.RedirectUri != redirectURI || !slices.Contains(client.RedirectUris, redirectURI) || len(verifier) < 43 || len(verifier) > 128 || subtle.ConstantTimeCompare([]byte(challenge), []byte(row.CodeChallenge)) != 1 {
		return row, dbq.User{}, service.ErrUnauthorized
	}
	user, err := credentialOwner(ctx, q, row.UserID, row.AgentID, clientID, row.Scope)
	return row, user, err
}

// RefreshOwner rechecks the unconsumed, client-bound opaque refresh credential
// under the exchange transaction's row lock before authorizing its live owner.
func RefreshOwner(ctx context.Context, q *dbq.Queries, raw, clientID string) (dbq.User, error) {
	sum := sha256.Sum256([]byte(raw))
	row, err := q.GetRefreshTokenByHashForUpdate(ctx, sum[:])
	if err != nil {
		return dbq.User{}, err
	}
	if row.ClientID != clientID || row.ConsumedAt.Valid || !row.ExpiresAt.Valid || !row.ExpiresAt.Time.After(time.Now()) {
		return dbq.User{}, service.ErrUnauthorized
	}
	client, err := q.GetOAuthClient(ctx, clientID)
	if err != nil {
		return dbq.User{}, err
	}
	if client.TokenEndpointAuthMethod != "none" || !slices.Contains(client.GrantTypes, "refresh_token") || !auth.ScopeContains(client.Scope, "mcp") {
		return dbq.User{}, service.ErrUnauthorized
	}
	return credentialOwner(ctx, q, row.UserID, row.AgentID, clientID, row.Scope)
}

func credentialOwner(ctx context.Context, q *dbq.Queries, userID, agentID pgtype.UUID, clientID, scope string) (dbq.User, error) {
	user, err := q.GetUserByID(ctx, userID)
	if err != nil {
		return dbq.User{}, err
	}
	if user.MustChangePassword {
		return dbq.User{}, service.ErrForbidden
	}
	grant, err := q.GetActiveGrant(ctx, dbq.GetActiveGrantParams{UserID: userID, ClientID: clientID, AgentID: agentID})
	if err != nil {
		return dbq.User{}, err
	}
	if !auth.ScopeContains(scope, "mcp") || !auth.ScopeContains(grant.Scope, "mcp") {
		return dbq.User{}, service.ErrForbidden
	}
	p := authz.UserPrincipal(uuid.UUID(user.ID.Bytes), auth.Role(user.TenantRole))
	if err := Entitle(ctx, q, p, uuid.UUID(agentID.Bytes)); err != nil {
		return dbq.User{}, err
	}
	return user, nil
}

func ListGrants(ctx context.Context, q *dbq.Queries, p authz.Principal) ([]dbq.ListGrantsForUserRow, error) {
	if err := authz.Authorize(ctx, q, p, authz.AccountOAuthManage, uuid.Nil); err != nil {
		return nil, err
	}
	return q.ListGrantsForUser(ctx, pg(p.UserID))
}

func RevokeGrant(ctx context.Context, database *db.DB, p authz.Principal, clientID string, agentID uuid.UUID) error {
	if database == nil {
		panic("inboundoauth: database is required")
	}
	tx, err := database.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.Authorize(ctx, q, p, authz.AccountOAuthManage, uuid.Nil); err != nil {
		return err
	}
	if err := q.LockOAuthGrantLifecycle(ctx, dbq.LockOAuthGrantLifecycleParams{UserID: p.UserID.String(), ClientID: clientID, AgentID: agentID.String()}); err != nil {
		return err
	}
	if _, err := q.DeleteOAuthConsentTransactionsForGrant(ctx, dbq.DeleteOAuthConsentTransactionsForGrantParams{UserID: pg(p.UserID), ClientID: clientID, AgentID: pg(agentID)}); err != nil {
		return err
	}
	if _, err := q.RevokeGrant(ctx, dbq.RevokeGrantParams{UserID: pg(p.UserID), ClientID: clientID, AgentID: pg(agentID)}); err != nil {
		return err
	}
	if _, err := q.RevokeRefreshForGrant(ctx, dbq.RevokeRefreshForGrantParams{UserID: pg(p.UserID), ClientID: clientID, AgentID: pg(agentID)}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
