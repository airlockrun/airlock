package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BridgeFieldsToProto packs the union of a Bridge row plus an
// optional owner join into the wire BridgeInfo. The settings JSONB
// is decoded via bridgessvc.DecodeSettings so every caller sees the
// same defaulted view.
func BridgeFieldsToProto(
	id, agentID, ownerID pgtype.UUID,
	typ, name, botUsername, status string,
	createdAt, updatedAt pgtype.Timestamptz,
	ownerEmail, ownerDisplayName pgtype.Text,
	settingsJSON []byte,
) *airlockv1.BridgeInfo {
	settings := bridgessvc.DecodeSettings(settingsJSON)
	info := &airlockv1.BridgeInfo{
		Id:          PgUUIDToString(id),
		Name:        name,
		Type:        typ,
		BotUsername: botUsername,
		Status:      status,
		CreatedAt:   timestamppb.New(createdAt.Time),
		UpdatedAt:   timestamppb.New(updatedAt.Time),
		Settings: &airlockv1.BridgeSettings{
			AllowPublicDms:             settings.AllowPublicDMs,
			PublicSessionTtlSeconds:    int32(settings.PublicSessionTTLSeconds),
			PublicSessionMode:          settings.PublicSessionMode,
			PublicPromptTimeoutSeconds: int32(settings.PublicPromptTimeoutSeconds),
		},
	}
	if agentID.Valid {
		info.AgentId = PgUUIDToString(agentID)
	}
	if ownerID.Valid && ownerEmail.Valid {
		info.Owner = &airlockv1.UserSummary{
			Id:          PgUUIDToString(ownerID),
			Email:       ownerEmail.String,
			DisplayName: ownerDisplayName.String,
		}
	}
	return info
}

// BridgeRowToProto adapts a bare Bridge row (no owner join) to the
// wire BridgeInfo.
func BridgeRowToProto(br dbq.Bridge) *airlockv1.BridgeInfo {
	return BridgeFieldsToProto(
		br.ID, br.AgentID, br.OwnerID,
		br.Type, br.Name, br.BotUsername, br.Status,
		br.CreatedAt, br.UpdatedAt,
		pgtype.Text{}, pgtype.Text{},
		br.Settings,
	)
}

// BridgeResultToProto adapts a bridges service Result (bridge row +
// optional owner DTO) to the wire BridgeInfo. The Result's Owner
// field carries the JOIN result for handlers that need the resolved
// owner email/name; nil-Owner falls back to the row's OwnerID with
// blank owner-display fields.
func BridgeResultToProto(res bridgessvc.Result) *airlockv1.BridgeInfo {
	var ownerEmail, ownerName pgtype.Text
	var ownerID pgtype.UUID
	if res.Owner != nil {
		ownerEmail = pgtype.Text{String: res.Owner.Email, Valid: true}
		ownerName = pgtype.Text{String: res.Owner.DisplayName, Valid: true}
		ownerID = pgtype.UUID{Bytes: res.Owner.ID, Valid: true}
	} else {
		ownerID = res.Bridge.OwnerID
	}
	return BridgeFieldsToProto(
		res.Bridge.ID, res.Bridge.AgentID, ownerID,
		res.Bridge.Type, res.Bridge.Name, res.Bridge.BotUsername, res.Bridge.Status,
		res.Bridge.CreatedAt, res.Bridge.UpdatedAt,
		ownerEmail, ownerName,
		res.Bridge.Settings,
	)
}

// BridgeListItemToProto adapts a bridges service ListItem to the
// wire BridgeInfo. Same shape as Result but the JOIN's Owner pointer
// rides alongside the row instead of replacing OwnerID.
func BridgeListItemToProto(item bridgessvc.ListItem) *airlockv1.BridgeInfo {
	var ownerEmail, ownerName pgtype.Text
	if item.Owner != nil {
		ownerEmail = pgtype.Text{String: item.Owner.Email, Valid: true}
		ownerName = pgtype.Text{String: item.Owner.DisplayName, Valid: true}
	}
	return BridgeFieldsToProto(
		item.Bridge.ID, item.Bridge.AgentID, item.Bridge.OwnerID,
		item.Bridge.Type, item.Bridge.Name, item.Bridge.BotUsername, item.Bridge.Status,
		item.Bridge.CreatedAt, item.Bridge.UpdatedAt,
		ownerEmail, ownerName,
		item.Bridge.Settings,
	)
}
