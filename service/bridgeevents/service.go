// Package bridgeevents authorizes bridge controls against their exact persisted
// platform, account, conversation, and run binding.
package bridgeevents

import (
	"context"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Cancel accepts coordinates from the authenticated platform driver, not an
// Airlock user UUID. Database cancellation is committed before local signaling.
func Cancel(ctx context.Context, database *db.DB, bridgeID, runID uuid.UUID, senderID, chatID string) error {
	if database == nil {
		panic("bridgeevents: database is required")
	}
	if runID == uuid.Nil {
		return service.ErrInvalidInput
	}
	tx, err := database.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	claims, err := auth.AdmitBridge(ctx, q, bridgeID, senderID, chatID)
	if err != nil {
		return err
	}
	p := authz.PrincipalFromClaims(claims)
	if err := authz.Authorize(ctx, q, p, authz.BridgeRunCancel, uuid.Nil); err != nil {
		return err
	}
	bridge, err := q.GetBridgeByID(ctx, pgID(bridgeID))
	if err != nil {
		return err
	}
	var rows int64
	if bridge.IsSystem {
		rows, err = q.CancelBridgeSystemRun(ctx, dbq.CancelBridgeSystemRunParams{
			RunID: pgID(runID), BridgeID: bridge.ID, ChatID: chatID, SenderID: senderID,
			UserID: pgID(p.UserID), AuthEpoch: claims.AuthEpoch,
		})
	} else {
		rows, err = q.CancelBridgePromptRun(ctx, dbq.CancelBridgePromptRunParams{
			RunID: pgID(runID), BridgeID: bridge.ID, AgentID: bridge.AgentID, ChatID: chatID,
			SenderID: senderID, UserID: pgID(p.UserID), AuthEpoch: claims.AuthEpoch,
		})
	}
	if err != nil {
		return err
	}
	if rows != 1 {
		return service.ErrNotFound
	}
	if !bridge.IsSystem {
		if _, err := q.RequestConversationRunCancellation(ctx, pgID(runID)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func pgID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// AdmitPrompt binds a private bridge conversation to its live platform identity
// and target app. expectedUserID is a consistency assertion, never an identity
// source; the linked platform account supplies the principal.
func AdmitPrompt(ctx context.Context, q *dbq.Queries, agentID, bridgeID, expectedUserID uuid.UUID, chatID string) (authz.Principal, error) {
	claims, err := auth.AdmitBridge(ctx, q, bridgeID, chatID, chatID)
	if err != nil {
		return authz.Principal{}, err
	}
	principal := authz.PrincipalFromClaims(claims)
	bridge, err := q.GetBridgeByID(ctx, pgID(bridgeID))
	if err != nil {
		return authz.Principal{}, err
	}
	if principal.UserID != expectedUserID || bridge.IsSystem || !bridge.AgentID.Valid || uuid.UUID(bridge.AgentID.Bytes) != agentID {
		return authz.Principal{}, service.ErrForbidden
	}
	if err := authz.Authorize(ctx, q, principal, authz.AgentRuntimeInvoke, agentID); err != nil {
		return authz.Principal{}, err
	}
	return principal, nil
}
