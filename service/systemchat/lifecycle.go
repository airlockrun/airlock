package systemchat

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func Platform(p authz.Principal) string {
	if p.Identity == nil {
		return ""
	}
	if p.Identity.Provenance().Profile == "bridge" {
		return "telegram"
	}
	return "web"
}

// CancelRun serializes with admission and suspension on the conversation row.
func (s *Service) CancelRun(ctx context.Context, p authz.Principal, runID uuid.UUID) (bool, error) {
	p, err := s.authorize(ctx, p, authz.SystemRunCancel)
	if err != nil {
		return false, err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	run, err := q.GetSystemRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil || uuid.UUID(run.UserID.Bytes) != p.UserID {
		return false, service.ErrNotFound
	}
	conv, err := q.GetSystemConversationByIDForUpdate(ctx, run.ConversationID)
	if err != nil || uuid.UUID(conv.UserID.Bytes) != p.UserID {
		return false, service.ErrNotFound
	}
	p, err = FreshPrincipal(ctx, q, p)
	if err != nil {
		return false, err
	}
	if p.Identity.Provenance().Profile == "bridge" {
		origin := p.Identity.Provenance()
		if !conv.BridgeID.Valid || origin.BridgeID != uuid.UUID(conv.BridgeID.Bytes) || !conv.ExternalID.Valid || origin.ChatID != conv.ExternalID.String {
			return false, service.ErrForbidden
		}
	}
	n, err := q.CancelSystemRun(ctx, dbq.CancelSystemRunParams{ID: run.ID, ConversationID: conv.ID, UserID: conv.UserID})
	if err != nil {
		return false, err
	}
	if _, err := q.ClaimSystemConversationCheckpoint(ctx, dbq.ClaimSystemConversationCheckpointParams{ID: conv.ID, SuspendedRunID: run.ID}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return n == 1, nil
}

// CheckRun rechecks the original credential and durable cancellation before work.
func (s *Service) CheckRun(ctx context.Context, p authz.Principal, runID uuid.UUID) error {
	p, err := s.authorize(ctx, p, authz.SystemChat)
	if err != nil {
		return err
	}
	run, err := dbq.New(s.db.Pool()).GetSystemRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil || uuid.UUID(run.UserID.Bytes) != p.UserID {
		return service.ErrNotFound
	}
	if run.Status != "running" {
		return context.Canceled
	}
	// A new credential for the same user cannot substitute for a revoked origin.
	if _, err := s.RunPrincipal(ctx, runID); err != nil {
		return err
	}
	return nil
}

// ObserveRun makes cancellations and credential revocations visible on every replica.
// Database failures stop execution rather than letting an unvalidated turn continue.
func (s *Service) ObserveRun(ctx context.Context, p authz.Principal, runID uuid.UUID, cancel context.CancelFunc) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		checkCtx, done := context.WithTimeout(ctx, 5*time.Second)
		err := s.CheckRun(checkCtx, p, runID)
		done()
		if err != nil {
			cancel()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) PersistSuspension(ctx context.Context, conversationID, runID uuid.UUID, checkpoint []byte) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	conv, err := q.GetSystemConversationByIDForUpdate(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		return err
	}
	if conv.Status != "active" {
		return service.ErrConflict
	}
	n, err := q.SuspendSystemRun(ctx, dbq.SuspendSystemRunParams{ID: pgtype.UUID{Bytes: runID, Valid: true}, ConversationID: conv.ID})
	if err != nil {
		return err
	}
	if n != 1 {
		return service.ErrConflict
	}
	n, err = q.SetSystemConversationCheckpoint(ctx, dbq.SetSystemConversationCheckpointParams{ID: conv.ID, SuspendedRunID: pgtype.UUID{Bytes: runID, Valid: true}, Checkpoint: checkpoint})
	if err != nil {
		return err
	}
	if n != 1 {
		return service.ErrConflict
	}
	return tx.Commit(ctx)
}

func (s *Service) FinishRun(ctx context.Context, runID uuid.UUID, status, message string) error {
	if status != "complete" && status != "error" && status != "cancelled" {
		return service.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return dbq.New(s.db.Pool()).UpdateSystemRunStatus(ctx, dbq.UpdateSystemRunStatusParams{ID: pgtype.UUID{Bytes: runID, Valid: true}, Status: status, ErrorMessage: message})
}
