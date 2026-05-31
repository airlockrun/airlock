package sysagent

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Conversation + ConversationDetail are the wire shapes the HTTP handler hands to
// the frontend. They live here (not in proto) so the service stays
// proto-free; the handler does the proto conversion at the boundary.

// Conversation is one row from ListConversations / CreateConversation.
type Conversation struct {
	dbq.SystemConversation
}

// ConversationDetail bundles a conversation with its full message history. The
// caller decides whether to also request paginated tails separately
// for very long conversations (we don't paginate on the initial Get because
// chat conversations rarely grow beyond a few dozen messages — agent chat
// pages from the same shape).
type ConversationDetail struct {
	Conversation dbq.SystemConversation
	Messages     []dbq.SystemMessage
}

// ListConversations returns the caller's own conversations, newest-active first.
// Ownership is enforced at the query level — conversations aren't shared.
func (s *Service) ListConversations(ctx context.Context, p authz.Principal) ([]dbq.SystemConversation, error) {
	if !p.IsAuthenticatedUser() {
		return nil, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	return q.ListSystemConversationsByUser(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
}

// CreateConversation inserts a fresh conversation for the caller. title is
// optional; the DB default is "New chat".
func (s *Service) CreateConversation(ctx context.Context, p authz.Principal, title string) (dbq.SystemConversation, error) {
	if !p.IsAuthenticatedUser() {
		return dbq.SystemConversation{}, service.ErrUnauthorized
	}
	if title == "" {
		title = "New chat"
	}
	q := dbq.New(s.db.Pool())
	return q.CreateSystemConversation(ctx, dbq.CreateSystemConversationParams{
		UserID: pgtype.UUID{Bytes: p.UserID, Valid: true},
		Title:  title,
	})
}

// GetConversation returns the conversation + its full message history (including
// pre-checkpoint rows + checkpoint markers — the UI's full timeline,
// not the LLM context filter). 404 for a missing conversation, 404 (not
// 403) for someone else's — exposing existence to non-owners would
// leak metadata.
func (s *Service) GetConversation(ctx context.Context, p authz.Principal, conversationID uuid.UUID) (ConversationDetail, error) {
	if !p.IsAuthenticatedUser() {
		return ConversationDetail{}, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	conversation, err := q.GetSystemConversationByID(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		return ConversationDetail{}, service.ErrNotFound
	}
	if uuid.UUID(conversation.UserID.Bytes) != p.UserID {
		return ConversationDetail{}, service.ErrNotFound
	}
	msgs, err := q.ListSystemMessagesByConversationAll(ctx, conversation.ID)
	if err != nil {
		return ConversationDetail{}, err
	}
	return ConversationDetail{Conversation: conversation, Messages: msgs}, nil
}

// DeleteConversation removes a conversation (and via ON DELETE CASCADE its
// messages, runs, and any pending checkpoint state). audit rows for
// the conversation stay (ON DELETE SET NULL preserves forensics — what
// happened in a now-deleted conversation is still recoverable).
func (s *Service) DeleteConversation(ctx context.Context, p authz.Principal, conversationID uuid.UUID) error {
	if !p.IsAuthenticatedUser() {
		return service.ErrUnauthorized
	}
	// Confirm ownership before the delete so a wrong-user request
	// gets 404, not a silent no-op. The query itself is
	// owner-scoped, but we want the explicit "not found" signal.
	q := dbq.New(s.db.Pool())
	conversation, err := q.GetSystemConversationByID(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if uuid.UUID(conversation.UserID.Bytes) != p.UserID {
		return service.ErrNotFound
	}
	return q.DeleteSystemConversation(ctx, dbq.DeleteSystemConversationParams{
		ID:     pgtype.UUID{Bytes: conversationID, Valid: true},
		UserID: pgtype.UUID{Bytes: p.UserID, Valid: true},
	})
}
