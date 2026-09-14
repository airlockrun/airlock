package systemchat

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// EnsureBridgeConversation derives every routing coordinate from the poller's
// live admission proof. No user ID, bridge ID or chat ID is accepted separately.
func (s *Service) EnsureBridgeConversation(ctx context.Context, p authz.Principal) (dbq.SystemConversation, error) {
	p, err := s.authorize(ctx, p, authz.SystemConversationManage)
	if err != nil {
		return dbq.SystemConversation{}, err
	}
	origin := p.Identity.Provenance()
	if origin.Profile != "bridge" || origin.AgentID != uuid.Nil {
		return dbq.SystemConversation{}, service.ErrForbidden
	}
	q := dbq.New(s.db.Pool())
	bridgeID := pgtype.UUID{Bytes: origin.BridgeID, Valid: true}
	bridge, err := q.GetBridgeByID(ctx, bridgeID)
	if err != nil || !bridge.IsSystem || bridge.AgentID.Valid {
		return dbq.SystemConversation{}, service.ErrForbidden
	}
	return q.EnsureSystemConversationForBridge(ctx, dbq.EnsureSystemConversationForBridgeParams{UserID: pgtype.UUID{Bytes: p.UserID, Valid: true}, BridgeID: bridgeID, ExternalID: pgtype.Text{String: origin.ChatID, Valid: true}, Title: bridge.Name})
}
