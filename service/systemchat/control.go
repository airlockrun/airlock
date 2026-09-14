package systemchat

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Control serializes conversation controls with run admission and history writes.
func (s *Service) Control(ctx context.Context, p authz.Principal, conversationID uuid.UUID, command, args string) (bool, error) {
	action := authz.SystemConversationManage
	if command == "cancel" {
		action = authz.SystemRunCancel
	}
	p, err := s.authorize(ctx, p, action)
	if err != nil {
		return false, err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	conv, err := q.GetSystemConversationByIDForUpdate(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil || uuid.UUID(conv.UserID.Bytes) != p.UserID {
		return false, service.ErrNotFound
	}
	p, err = FreshPrincipal(ctx, q, p)
	if err != nil {
		return false, err
	}
	if proof := p.Identity.Provenance(); proof.Profile == "bridge" && (proof.BridgeID != uuid.UUID(conv.BridgeID.Bytes) || proof.ChatID != conv.ExternalID.String) {
		return false, service.ErrForbidden
	}
	var result bool
	switch command {
	case "cancel", "clear":
		n, err := q.CancelSystemConversationRuns(ctx, dbq.CancelSystemConversationRunsParams{ConversationID: conv.ID, UserID: conv.UserID})
		if err != nil {
			return false, err
		}
		result = n > 0
		if err := q.ClearSystemConversationCheckpoint(ctx, conv.ID); err != nil {
			return false, err
		}
		if command == "clear" {
			result = conv.SuspendedRunID.Valid
			marker, err := q.AppendSystemMessage(ctx, dbq.AppendSystemMessageParams{ConversationID: conv.ID, Role: "system", Source: "checkpoint", Parts: []byte(`[{"type":"checkpoint","kind":"clear"}]`), CostEstimate: pgNumericFromFloat(0)})
			if err != nil {
				return false, err
			}
			if err := q.SetSystemConversationContextCheckpoint(ctx, dbq.SetSystemConversationContextCheckpointParams{ID: conv.ID, CheckpointMessageID: marker.ID}); err != nil {
				return false, err
			}
		}
	case "echo":
		switch args {
		case "on":
			result = true
		case "off":
			result = false
		case "":
			var settings struct {
				Echo bool `json:"echo"`
			}
			if err := json.Unmarshal(conv.Settings, &settings); err != nil {
				return false, err
			}
			result = !settings.Echo
		default:
			return false, service.ErrInvalidInput
		}
		patch, err := json.Marshal(map[string]bool{"echo": result})
		if err != nil {
			return false, err
		}
		if err := q.UpdateSystemConversationSettings(ctx, dbq.UpdateSystemConversationSettingsParams{ID: conv.ID, Patch: patch}); err != nil {
			return false, err
		}
	default:
		return false, service.ErrInvalidInput
	}
	return result, tx.Commit(ctx)
}
