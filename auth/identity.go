package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Identity retains verified credential provenance without exposing mutable
// authorization claims. Token validation or authenticated platform admission
// produces one. It can be rechecked at each action in a long-running turn.
type Identity struct {
	claims Claims
	bridge *bridgeCredential
}

// Provenance contains credential coordinates for durable run attribution. It
// contains no role or access authority and cannot be used to construct Identity.
type Provenance struct {
	Profile            string
	UserID             uuid.UUID
	SessionID          uuid.UUID
	AuthEpoch          int64
	ExpiresAt          time.Time
	AuthenticatedAt    time.Time
	Audience           string
	ClientID           string
	Scope              string
	AgentID            uuid.UUID
	BridgeID           uuid.UUID
	PlatformIdentityID uuid.UUID
	SenderID           string
	ChatID             string
}

func (i *Identity) Provenance() Provenance {
	if i == nil {
		panic("auth: identity is required")
	}
	p := Provenance{Profile: i.claims.TokenUse, UserID: uuid.MustParse(i.claims.Subject), AuthEpoch: i.claims.AuthEpoch, ClientID: i.claims.ClientID, Scope: i.claims.Scope}
	if i.claims.SessionID != "" {
		p.SessionID = uuid.MustParse(i.claims.SessionID)
	}
	if i.claims.ExpiresAt != nil {
		p.ExpiresAt = i.claims.ExpiresAt.Time
	}
	if i.claims.AuthTime != nil {
		p.AuthenticatedAt = i.claims.AuthTime.Time
	}
	if len(i.claims.Audience) == 1 {
		p.Audience = i.claims.Audience[0]
	}
	if i.claims.AgentID != "" {
		p.AgentID = uuid.MustParse(i.claims.AgentID)
	}
	if i.bridge != nil {
		p.Profile, p.BridgeID, p.PlatformIdentityID, p.SenderID, p.ChatID = "bridge", i.bridge.bridgeID, i.bridge.identityID, i.bridge.senderID, i.bridge.chatID
		if i.bridge.agentID.Valid {
			p.AgentID = uuid.UUID(i.bridge.agentID.Bytes)
		}
	}
	return p
}

func sealIdentity(claims *Claims) *Identity {
	snapshot := *claims
	snapshot.identity, snapshot.credential = nil, nil
	snapshot.Audience = append(jwt.ClaimStrings(nil), claims.Audience...)
	for _, date := range []**jwt.NumericDate{&snapshot.ExpiresAt, &snapshot.IssuedAt, &snapshot.NotBefore, &snapshot.AuthTime} {
		if *date != nil {
			copy := **date
			*date = &copy
		}
	}
	return &Identity{claims: snapshot}
}

func (c *Claims) Identity() *Identity {
	if c == nil {
		return nil
	}
	return c.identity
}

// Resolve refreshes account and session state without trusting a caller's role.
func (i *Identity) Resolve(ctx context.Context, q *dbq.Queries) (*Claims, error) {
	if i != nil && i.bridge != nil {
		live, err := AdmitBridge(ctx, q, i.bridge.bridgeID, i.bridge.senderID, i.bridge.chatID)
		if err != nil || live.Subject != i.claims.Subject || live.AuthEpoch != i.claims.AuthEpoch || *live.identity.bridge != *i.bridge {
			return nil, apperr.ErrUnauthorized
		}
		return live, nil
	}
	if i == nil || !i.claims.verified || i.claims.ExpiresAt == nil || !i.claims.ExpiresAt.Time.After(time.Now()) {
		return nil, apperr.ErrUnauthorized
	}
	copy := sealIdentity(&i.claims)
	return ResolveLiveUserClaims(ctx, q, &copy.claims, i.claims.TokenUse != tokenUseOAuthMCP)
}

// RequireSecuredAccount is shared by non-recovery admission surfaces.
func RequireSecuredAccount(claims *Claims) error {
	if claims == nil {
		return apperr.ErrUnauthorized
	}
	if claims.MustChangePassword {
		return apperr.ErrForbidden
	}
	return nil
}

// AdmitUserAccess performs profile validation and live first-party admission.
// Account recovery endpoints apply their narrow secured-account allowlist.
func AdmitUserAccess(ctx context.Context, q *dbq.Queries, secret, token string) (*Claims, error) {
	claims, err := ValidateUserAccessToken(secret, token)
	if err != nil {
		return nil, err
	}
	return ResolveLiveUserClaims(ctx, q, claims, true)
}

// AdmitSubdomain accepts exactly one explicit user bearer or one agent-bound
// cookie. Missing credentials are distinct from invalid supplied credentials.
func AdmitSubdomain(r *http.Request, q *dbq.Queries, secret string, agentID uuid.UUID) (claims *Claims, fromCookie, supplied bool, err error) {
	token, supplied, err := RequestBearerToken(r)
	if err != nil {
		return nil, false, supplied, err
	}
	if !supplied {
		cookie, cookieErr := UniqueCookie(r, "__air_session")
		if cookieErr == http.ErrNoCookie {
			return nil, false, false, apperr.ErrUnauthorized
		}
		if cookieErr != nil {
			return nil, true, true, cookieErr
		}
		token, fromCookie, supplied = cookie.Value, true, true
	}
	if fromCookie {
		claims, err = ValidateSubdomainToken(secret, token, agentID)
	} else {
		claims, err = ValidateUserAccessToken(secret, token)
	}
	if err != nil {
		return nil, fromCookie, supplied, err
	}
	claims, err = ResolveLiveUserClaims(r.Context(), q, claims, true)
	if err != nil {
		return nil, fromCookie, supplied, err
	}
	if err := RequireSecuredAccount(claims); err != nil {
		return nil, fromCookie, supplied, err
	}
	return claims, fromCookie, supplied, nil
}
