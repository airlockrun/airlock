package auth

import (
	"context"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type bridgeCredential struct {
	bridgeID   uuid.UUID
	senderID   string
	chatID     string
	identityID uuid.UUID
	agentID    pgtype.UUID
	system     bool
}

// AdmitBridge admits a private message received by Airlock's authenticated
// Telegram poller. A transport supplies platform coordinates, never an Airlock
// user UUID or role. Linked identity and account state are resolved live.
func AdmitBridge(ctx context.Context, q *dbq.Queries, bridgeID uuid.UUID, senderID, chatID string) (*Claims, error) {
	if q == nil {
		panic("auth: bridge admission queries are required")
	}
	if bridgeID == uuid.Nil || senderID == "" || chatID != senderID {
		return nil, apperr.ErrUnauthorized
	}
	bridge, err := q.GetBridgeByID(ctx, pgtype.UUID{Bytes: bridgeID, Valid: true})
	if err != nil || bridge.Status != "active" || bridge.Type != "telegram" {
		return nil, apperr.ErrUnauthorized
	}
	linked, err := q.GetPlatformIdentity(ctx, dbq.GetPlatformIdentityParams{Platform: bridge.Type, PlatformUserID: senderID})
	if err != nil || !linked.UserID.Valid || uuid.UUID(linked.UserID.Bytes) == uuid.Nil {
		return nil, apperr.ErrUnauthorized
	}
	user, err := q.GetUserByID(ctx, linked.UserID)
	if err != nil || !Role(user.TenantRole).Valid() {
		return nil, apperr.ErrUnauthorized
	}
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: uuid.UUID(user.ID.Bytes).String()},
		Email:            user.Email, DisplayName: user.DisplayName, TenantRole: user.TenantRole,
		AuthEpoch: user.AuthEpoch, MustChangePassword: user.MustChangePassword,
	}
	if err := RequireSecuredAccount(claims); err != nil {
		return nil, err
	}
	claims.identity = &Identity{claims: *claims, bridge: &bridgeCredential{bridgeID: bridgeID, senderID: senderID, chatID: chatID, identityID: uuid.UUID(linked.ID.Bytes), agentID: bridge.AgentID, system: bridge.IsSystem}}
	return claims, nil
}
