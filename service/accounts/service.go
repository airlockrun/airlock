// Package accounts owns self-profile, session, and subscription projections.
package accounts

import (
	"context"
	"errors"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type Profile struct {
	User    dbq.User
	Actions []authz.Action
}

func Self(ctx context.Context, q *dbq.Queries, p authz.Principal) (Profile, error) {
	if err := authz.Authorize(ctx, q, p, authz.AccountSelfView, uuid.Nil); err != nil {
		return Profile{}, err
	}
	user, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		return Profile{}, err
	}
	return Profile{User: user, Actions: authz.GrantedTenantActions(auth.Role(user.TenantRole))}, nil
}

func ListSessions(ctx context.Context, q *dbq.Queries, p authz.Principal) ([]dbq.UserSession, error) {
	if err := authz.Authorize(ctx, q, p, authz.AccountSessionsManage, uuid.Nil); err != nil {
		return nil, err
	}
	return q.ListUserSessionsByUser(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
}

// RevokeSession is idempotent and never reveals another user's session.
func RevokeSession(ctx context.Context, q *dbq.Queries, p authz.Principal, sessionID uuid.UUID) error {
	if err := authz.Authorize(ctx, q, p, authz.AccountSessionsManage, uuid.Nil); err != nil {
		return err
	}
	_, err := q.RevokeUserSessionByID(ctx, dbq.RevokeUserSessionByIDParams{ID: pgtype.UUID{Bytes: sessionID, Valid: true}, UserID: pgtype.UUID{Bytes: p.UserID, Valid: true}})
	return err
}

func InspectDeviceLogin(ctx context.Context, q *dbq.Queries, p authz.Principal, codeHash string) (dbq.DeviceLoginSession, error) {
	if err := authz.Authorize(ctx, q, p, authz.AccountDeviceLogin, uuid.Nil); err != nil {
		return dbq.DeviceLoginSession{}, err
	}
	return q.GetDeviceLoginByUserCodeHash(ctx, codeHash)
}

func ApproveDeviceLogin(ctx context.Context, q *dbq.Queries, p authz.Principal, codeHash string) (dbq.DeviceLoginSession, error) {
	if err := authz.Authorize(ctx, q, p, authz.AccountDeviceLogin, uuid.Nil); err != nil {
		return dbq.DeviceLoginSession{}, err
	}
	return q.ApproveDeviceLogin(ctx, dbq.ApproveDeviceLoginParams{UserID: pgtype.UUID{Bytes: p.UserID, Valid: true}, UserCodeHash: codeHash})
}

func DenyDeviceLogin(ctx context.Context, q *dbq.Queries, p authz.Principal, codeHash string) (dbq.DeviceLoginSession, error) {
	if err := authz.Authorize(ctx, q, p, authz.AccountDeviceLogin, uuid.Nil); err != nil {
		return dbq.DeviceLoginSession{}, err
	}
	return q.DenyDeviceLogin(ctx, codeHash)
}

// Subscriptions projects explicit agent grants for the live account. Socket
// admission and revalidation use the same snapshot, including access changes.
func Subscriptions(ctx context.Context, q *dbq.Queries, p authz.Principal) (map[uuid.UUID]string, error) {
	if err := authz.Authorize(ctx, q, p, authz.AccountSubscriptionsView, uuid.Nil); err != nil {
		return nil, err
	}
	rows, err := q.ListUserAgentGrants(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]string, len(rows))
	for _, row := range rows {
		if !row.ID.Valid || uuid.UUID(row.ID.Bytes) == uuid.Nil {
			return nil, errors.New("invalid agent membership id")
		}
		switch row.Role {
		case "admin", "user", "public":
		default:
			return nil, errors.New("invalid agent membership access")
		}
		out[uuid.UUID(row.ID.Bytes)] = row.Role
	}
	return out, nil
}
