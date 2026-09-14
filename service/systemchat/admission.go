package systemchat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type PromptInput struct {
	Message string
	// Platform is display-only. Admission derives the channel from Identity.
	Platform    string
	Approved    *bool
	ResumeRunID string
}

func (s *Service) StartRun(ctx context.Context, p authz.Principal, conversationID uuid.UUID, input PromptInput) (uuid.UUID, dbq.SystemConversation, error) {
	if input.Message != "" && input.Approved != nil {
		return uuid.Nil, dbq.SystemConversation{}, service.ErrInvalidInput
	}
	p, err := s.authorize(ctx, p, authz.SystemChat)
	if err != nil {
		return uuid.Nil, dbq.SystemConversation{}, err
	}
	q := dbq.New(s.db.Pool())
	caller := p
	var resumeID uuid.UUID
	if input.Approved != nil && input.ResumeRunID == "" {
		return uuid.Nil, dbq.SystemConversation{}, service.Detail(service.ErrInvalidInput, "resume_run_id is required")
	}
	if input.ResumeRunID != "" {
		resumeID, err = uuid.Parse(input.ResumeRunID)
		if err != nil {
			return uuid.Nil, dbq.SystemConversation{}, service.ErrInvalidInput
		}
		// The confirmer's proof authorizes the response; the suspended run's
		// original credential remains the authority for its pending work.
		original, err := s.RunPrincipal(ctx, resumeID)
		if err != nil {
			return uuid.Nil, dbq.SystemConversation{}, err
		}
		if original.UserID != p.UserID {
			return uuid.Nil, dbq.SystemConversation{}, service.ErrNotFound
		}
		p = original
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		for {
			run, err := q.GetSystemRunByID(ctx, pgtype.UUID{Bytes: resumeID, Valid: true})
			if err != nil || uuid.UUID(run.UserID.Bytes) != p.UserID || uuid.UUID(run.ConversationID.Bytes) != conversationID {
				return uuid.Nil, dbq.SystemConversation{}, service.ErrNotFound
			}
			if run.Status == "suspended" {
				break
			}
			if run.Status != "running" {
				return uuid.Nil, dbq.SystemConversation{}, service.ErrConflict
			}
			select {
			case <-ctx.Done():
				return uuid.Nil, dbq.SystemConversation{}, ctx.Err()
			case <-deadline.C:
				return uuid.Nil, dbq.SystemConversation{}, service.ErrConflict
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return uuid.Nil, dbq.SystemConversation{}, err
	}
	defer tx.Rollback(ctx)
	q = q.WithTx(tx)
	conv, err := q.GetSystemConversationByIDForUpdate(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil || uuid.UUID(conv.UserID.Bytes) != p.UserID {
		return uuid.Nil, dbq.SystemConversation{}, service.ErrNotFound
	}
	// Revalidate after waiting for the conversation lock or confirmation.
	caller, err = FreshPrincipal(ctx, q, caller)
	if err != nil {
		return uuid.Nil, dbq.SystemConversation{}, err
	}
	p, err = FreshPrincipal(ctx, q, p)
	if err != nil {
		return uuid.Nil, dbq.SystemConversation{}, err
	}
	provenance := p.Identity.Provenance()
	if conv.Source == "bridge" {
		bridge, err := q.GetBridgeByID(ctx, conv.BridgeID)
		if err != nil || !bridge.IsSystem || bridge.AgentID.Valid {
			return uuid.Nil, dbq.SystemConversation{}, service.ErrForbidden
		}
	}
	for _, identity := range []*auth.Identity{caller.Identity, p.Identity} {
		proof := identity.Provenance()
		if conv.Source == "bridge" {
			if proof.Profile != "bridge" || proof.AgentID != uuid.Nil || !conv.BridgeID.Valid || proof.BridgeID != uuid.UUID(conv.BridgeID.Bytes) || !conv.ExternalID.Valid || proof.ChatID != conv.ExternalID.String {
				return uuid.Nil, dbq.SystemConversation{}, service.ErrForbidden
			}
		} else if proof.Profile != "user_access" || proof.AgentID != uuid.Nil {
			return uuid.Nil, dbq.SystemConversation{}, service.ErrForbidden
		}
	}
	resolving := input.Approved != nil || (input.Message != "" && conv.Status == "awaiting_confirmation")
	if resolving {
		if resumeID == uuid.Nil || conv.Status != "awaiting_confirmation" || !conv.SuspendedRunID.Valid || uuid.UUID(conv.SuspendedRunID.Bytes) != resumeID {
			return uuid.Nil, dbq.SystemConversation{}, service.ErrConflict
		}
		n, err := q.ResolveSuspendedSystemRun(ctx, dbq.ResolveSuspendedSystemRunParams{ID: conv.SuspendedRunID, ConversationID: conv.ID})
		if err != nil {
			return uuid.Nil, dbq.SystemConversation{}, err
		}
		if n != 1 {
			return uuid.Nil, dbq.SystemConversation{}, service.ErrConflict
		}
		n, err = q.ClaimSystemConversationCheckpoint(ctx, dbq.ClaimSystemConversationCheckpointParams{ID: conv.ID, SuspendedRunID: conv.SuspendedRunID})
		if err != nil {
			return uuid.Nil, dbq.SystemConversation{}, err
		}
		if n != 1 {
			return uuid.Nil, dbq.SystemConversation{}, service.ErrConflict
		}
	} else if conv.Status != "active" || resumeID != uuid.Nil {
		return uuid.Nil, dbq.SystemConversation{}, service.ErrConflict
	}
	if _, err := q.GetLatestRunningSystemRun(ctx, conv.ID); err == nil {
		return uuid.Nil, dbq.SystemConversation{}, service.ErrConflict
	} else if err != pgx.ErrNoRows {
		return uuid.Nil, dbq.SystemConversation{}, err
	}
	if input.Message != "" && conv.Title == defaultConversationTitle {
		conv.Title = truncate(input.Message, 100)
		if err := q.RenameSystemConversation(ctx, dbq.RenameSystemConversationParams{ID: conv.ID, UserID: conv.UserID, Title: conv.Title}); err != nil {
			return uuid.Nil, dbq.SystemConversation{}, err
		}
	}
	trigger := "prompt"
	if provenance.Profile == "bridge" {
		trigger = "bridge"
	}
	if input.Message == "" && input.Approved == nil {
		trigger = "event"
	}
	run, err := q.CreateSystemRun(ctx, dbq.CreateSystemRunParams{ConversationID: conv.ID, UserID: conv.UserID, TriggerType: trigger})
	if err != nil {
		return uuid.Nil, dbq.SystemConversation{}, err
	}
	origin, err := json.Marshal(provenance)
	if err != nil {
		return uuid.Nil, dbq.SystemConversation{}, err
	}
	if err := q.CreateSystemRunOrigin(ctx, dbq.CreateSystemRunOriginParams{RunID: run.ID, Provenance: origin}); err != nil {
		return uuid.Nil, dbq.SystemConversation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, dbq.SystemConversation{}, err
	}
	return uuid.UUID(run.ID.Bytes), conv, nil
}

// RunPrincipal restores the exact original admission, including for follow-ups.
func (s *Service) RunPrincipal(ctx context.Context, runID uuid.UUID) (authz.Principal, error) {
	q := dbq.New(s.db.Pool())
	run, err := q.GetSystemRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		return authz.Principal{}, service.ErrNotFound
	}
	if run.Status == "cancelled" || run.Status == "error" {
		return authz.Principal{}, service.ErrConflict
	}
	raw, err := q.GetSystemRunOrigin(ctx, run.ID)
	if err != nil {
		return authz.Principal{}, service.ErrUnauthorized
	}
	var origin auth.Provenance
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&origin); err != nil {
		return authz.Principal{}, service.ErrUnauthorized
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return authz.Principal{}, service.ErrUnauthorized
	}
	claims, err := auth.RestoreSystemRunIdentity(ctx, q, runID)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) || errors.Is(err, service.ErrConflict) {
			return authz.Principal{}, err
		}
		return authz.Principal{}, service.ErrUnauthorized
	}
	p, err := s.authorize(ctx, authz.PrincipalFromClaims(claims), authz.SystemChat)
	if err != nil {
		return authz.Principal{}, err
	}
	actual := p.Identity.Provenance()
	origin.ExpiresAt, actual.ExpiresAt = origin.ExpiresAt.UTC(), actual.ExpiresAt.UTC()
	origin.AuthenticatedAt, actual.AuthenticatedAt = origin.AuthenticatedAt.UTC(), actual.AuthenticatedAt.UTC()
	if origin != actual || p.UserID != uuid.UUID(run.UserID.Bytes) {
		return authz.Principal{}, service.ErrUnauthorized
	}
	conv, err := q.GetSystemConversationByID(ctx, run.ConversationID)
	if err != nil || conv.UserID != run.UserID {
		return authz.Principal{}, service.ErrNotFound
	}
	if origin.Profile == "bridge" {
		bridge, err := q.GetBridgeByID(ctx, conv.BridgeID)
		if err != nil || !bridge.IsSystem || bridge.AgentID.Valid || origin.BridgeID != uuid.UUID(conv.BridgeID.Bytes) || origin.ChatID != conv.ExternalID.String {
			return authz.Principal{}, service.ErrForbidden
		}
	}
	return p, nil
}

func (s *Service) ResumePrincipal(ctx context.Context, conversationID, originRunID uuid.UUID) (authz.Principal, error) {
	p, err := s.RunPrincipal(ctx, originRunID)
	if err != nil {
		return authz.Principal{}, err
	}
	run, err := dbq.New(s.db.Pool()).GetSystemRunByID(ctx, pgtype.UUID{Bytes: originRunID, Valid: true})
	if err != nil || uuid.UUID(run.ConversationID.Bytes) != conversationID {
		return authz.Principal{}, service.ErrNotFound
	}
	return p, nil
}
