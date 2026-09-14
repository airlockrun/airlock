package auth

import (
	"context"
	"errors"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const RecentAuthenticationWindow = 10 * time.Minute

// ResolveLiveUserClaims rejects tokens for deleted users, stale auth epochs,
// and, when requireSession is true, revoked or expired first-party sessions.
// It returns authorization claims populated from the current user row.
func ResolveLiveUserClaims(ctx context.Context, q *dbq.Queries, claims *Claims, requireSession bool) (*Claims, error) {
	if q == nil {
		panic("auth: live user queries are required")
	}
	if claims == nil {
		return nil, errors.New("missing claims")
	}
	if claims.credential != nil {
		claims = &sealIdentity(&claims.credential.claims).claims
	}
	if claims.verified && requireSession != (claims.TokenUse != tokenUseOAuthMCP) {
		return nil, errors.New("session requirement does not match token profile")
	}
	if claims.verified && (claims.ExpiresAt == nil || !claims.ExpiresAt.Time.After(time.Now())) {
		return nil, errors.New("expired credential")
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil || userID == uuid.Nil {
		return nil, errors.New("invalid user subject")
	}

	var user dbq.User
	if requireSession {
		sessionID, err := uuid.Parse(claims.SessionID)
		if err != nil || sessionID == uuid.Nil {
			return nil, errors.New("invalid session id")
		}
		row, err := q.GetLiveUserForSession(ctx, dbq.GetLiveUserForSessionParams{
			SessionID: pgtype.UUID{Bytes: sessionID, Valid: true},
			UserID:    pgtype.UUID{Bytes: userID, Valid: true},
		})
		if err != nil {
			return nil, errors.New("inactive user session")
		}
		user = row.User
	} else {
		user, err = q.GetUserByID(ctx, pgtype.UUID{Bytes: userID, Valid: true})
		if err != nil {
			return nil, errors.New("user does not exist")
		}
	}
	if claims.AuthEpoch != user.AuthEpoch {
		return nil, errors.New("stale authentication epoch")
	}
	if !Role(user.TenantRole).Valid() {
		return nil, errors.New("invalid live tenant role")
	}
	if claims.verified && claims.TokenUse == tokenUseOAuthMCP {
		if err := verifyLiveOAuthGrant(ctx, q, claims, userID); err != nil {
			return nil, err
		}
	}

	live := *claims
	live.Email = user.Email
	live.DisplayName = user.DisplayName
	live.TenantRole = user.TenantRole
	live.MustChangePassword = user.MustChangePassword
	if live.verified {
		live.identity = sealIdentity(&live)
		live.credential = live.identity
	}
	return &live, nil
}

// SessionIDFromContext returns the current first-party session ID, if present.
func SessionIDFromContext(ctx context.Context) uuid.UUID {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return uuid.Nil
	}
	id, _ := uuid.Parse(claims.SessionID)
	return id
}
