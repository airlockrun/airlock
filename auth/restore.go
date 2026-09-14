package auth

import (
	"context"
	"errors"
	"net/url"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ErrRunAuthorityRevoked marks a denial established by authoritative persisted
// state. Lookup failures and delivery lease expiry must not carry this marker.
var ErrRunAuthorityRevoked = errors.New("run authority revoked")

// RestoreRunIdentity reads only immutable, host-written run origin records.
// No API accepts raw Provenance as a credential. Durable jobs return live account
// claims without a transferable Identity: their authorization must be resolved
// from this run again for every operation, independent of browser token lifetime.
func RestoreRunIdentity(ctx context.Context, q *dbq.Queries, runID uuid.UUID) (*Claims, error) {
	if q == nil {
		panic("auth: restore queries are required")
	}
	run, err := q.GetRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		return nil, err
	}
	o, err := q.GetRunOrigin(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	if o.Actor != "user" || !o.UserID.Valid || o.AgentID != run.AgentID {
		return nil, apperr.ErrUnauthorized
	}
	if run.ExecutionKind == "job" {
		switch o.CredentialProfile {
		case "bridge", tokenUseUserAccess, tokenUseSubdomain:
		case tokenUseOAuthMCP:
			resource, err := url.Parse(o.Audience.String)
			if err != nil || resource.Host == "" || resource.RawQuery != "" || resource.Fragment != "" || resource.User != nil || (resource.Scheme != "http" && resource.Scheme != "https") || resource.Path != "/api/agent/"+uuid.UUID(run.AgentID.Bytes).String()+"/mcp" {
				return nil, apperr.ErrUnauthorized
			}
		default:
			return nil, apperr.ErrUnauthorized
		}
		user, err := q.GetDurableOriginUser(ctx, o.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.Join(ErrRunAuthorityRevoked, apperr.ErrUnauthorized)
		}
		if err != nil {
			return nil, err
		}
		if !Role(user.TenantRole).Valid() {
			return nil, errors.Join(ErrRunAuthorityRevoked, apperr.ErrUnauthorized)
		}
		return &Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: uuid.UUID(user.ID.Bytes).String()},
			Email: user.Email, DisplayName: user.DisplayName, TenantRole: user.TenantRole, AuthEpoch: user.AuthEpoch}, nil
	}
	if o.CredentialProfile == "bridge" {
		claims, err := AdmitBridge(ctx, q, uuid.UUID(o.BridgeID.Bytes), o.SenderID.String, o.ChatID.String)
		if err != nil {
			return nil, err
		}
		p := claims.Identity().Provenance()
		if p.UserID != uuid.UUID(o.UserID.Bytes) || p.AuthEpoch != o.AuthEpoch.Int64 || p.PlatformIdentityID != uuid.UUID(o.PlatformIdentityID.Bytes) || (pgtype.UUID{Bytes: p.AgentID, Valid: p.AgentID != uuid.Nil}) != o.CredentialAgentID {
			return nil, apperr.ErrUnauthorized
		}
		return claims, nil
	}
	c := &Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: uuid.UUID(o.UserID.Bytes).String(), Audience: jwt.ClaimStrings{o.Audience.String}},
		TokenUse: o.CredentialProfile, AuthEpoch: o.AuthEpoch.Int64, ClientID: o.ClientID.String, Scope: o.Scope.String, verified: true}
	if o.SessionID.Valid {
		c.SessionID = uuid.UUID(o.SessionID.Bytes).String()
	}
	if o.CredentialAgentID.Valid {
		c.AgentID = uuid.UUID(o.CredentialAgentID.Bytes).String()
	}
	if o.CredentialExpiresAt.Valid {
		c.ExpiresAt = jwt.NewNumericDate(o.CredentialExpiresAt.Time)
	}
	if o.AuthenticatedAt.Valid {
		c.AuthTime = jwt.NewNumericDate(o.AuthenticatedAt.Time)
	}
	if c.TokenUse != tokenUseUserAccess && c.TokenUse != tokenUseSubdomain && c.TokenUse != tokenUseOAuthMCP {
		return nil, apperr.ErrUnauthorized
	}
	live, err := ResolveLiveUserClaims(ctx, q, c, c.TokenUse != tokenUseOAuthMCP)
	if err != nil {
		return nil, apperr.ErrUnauthorized
	}
	if err := RequireSecuredAccount(live); err != nil {
		return nil, err
	}
	return live, nil
}
