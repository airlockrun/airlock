// Package conversations owns the read/list/delete + topic-subscription
// lifecycle of web conversation threads. The streaming Prompt and
// multipart UploadFile endpoints stay HTTP-shaped in the api package
// (they manage NDJSON streams, conversation locks, and multipart form
// parsing that don't fit cleanly behind a Go-typed service surface).
package conversations

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// KeyExtractor returns the canonical S3 keys referenced by a message's
// parts JSON. Injected to avoid importing the api package.
type KeyExtractor func(parts []byte, agentID string) []string

type Service struct {
	db          *db.DB
	s3          *storage.S3Client
	logger      *zap.Logger
	extractKeys KeyExtractor
}

// New constructs the conversations service. s3 and extractKeys may be
// nil — they are only consulted by Delete's best-effort attachment
// cleanup; with either nil, Delete just skips the S3 scheduling step.
// The Delete row write still happens.
func New(d *db.DB, s3 *storage.S3Client, logger *zap.Logger, extractKeys KeyExtractor) *Service {
	if d == nil {
		panic("conversations: db is required")
	}
	if logger == nil {
		panic("conversations: logger is required")
	}
	return &Service{db: d, s3: s3, logger: logger, extractKeys: extractKeys}
}

func toPg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// Create makes a new web conversation thread.
func (s *Service) Create(ctx context.Context, userID, agentID uuid.UUID, title string) (dbq.AgentConversation, error) {
	if userID == uuid.Nil {
		return dbq.AgentConversation{}, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	conv, err := q.CreateWebConversation(ctx, dbq.CreateWebConversationParams{
		AgentID: toPg(agentID), UserID: toPg(userID), Title: title,
	})
	if err != nil {
		s.logger.Error("create conversation", zap.Error(err))
		return dbq.AgentConversation{}, err
	}
	return conv, nil
}

// ListByAgent returns web conversations owned by the user for the given
// agent (DM-only — there is at most one).
func (s *Service) ListByAgent(ctx context.Context, userID, agentID uuid.UUID) ([]dbq.AgentConversation, error) {
	if userID == uuid.Nil {
		return nil, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	rows, err := q.ListConversationsByAgent(ctx, dbq.ListConversationsByAgentParams{
		AgentID: toPg(agentID), UserID: toPg(userID),
	})
	if err != nil {
		s.logger.Error("list conversations", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// ListAll returns every web conversation the user owns, across all
// agents (newest first).
func (s *Service) ListAll(ctx context.Context, userID uuid.UUID) ([]dbq.AgentConversation, error) {
	if userID == uuid.Nil {
		return nil, service.ErrUnauthorized
	}
	rows, err := dbq.New(s.db.Pool()).ListAllWebConversationsByUser(ctx, toPg(userID))
	if err != nil {
		s.logger.Error("list all conversations", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// PendingConfirmation describes a suspended run's outstanding tool
// call awaiting user approval.
type PendingConfirmation struct {
	ToolCallID string
	ToolName   string
	Permission string
	Patterns   []string
	Code       string
	Input      string
}

// Detail is the GetConversation response payload.
type Detail struct {
	Conversation        dbq.AgentConversation
	Messages            []dbq.AgentMessage
	HasOlderMessages    bool
	InFlightRunID       string
	PendingConfirmation *PendingConfirmation
}

// Get returns the conversation + the newest page of messages + any
// in-flight or suspended-run metadata the chat store needs to adopt.
// Owner + surface gate: caller must own it; a2a transport rows are
// invisible from the web. Both fail with ErrNotFound (don't leak which
// conversations exist on which surface).
func (s *Service) Get(ctx context.Context, userID, convID uuid.UUID) (Detail, error) {
	if userID == uuid.Nil {
		return Detail{}, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	conv, err := q.GetConversationByID(ctx, toPg(convID))
	if err != nil ||
		!conv.UserID.Valid || uuid.UUID(conv.UserID.Bytes) != userID ||
		conv.Source == "a2a" {
		return Detail{}, service.ErrNotFound
	}
	msgs, err := q.ListMessagesByConversation(ctx, toPg(convID))
	if err != nil {
		s.logger.Error("list messages", zap.Error(err))
		return Detail{}, err
	}
	hasOlder := len(msgs) > 100
	if hasOlder {
		msgs = msgs[1:]
	}
	det := Detail{Conversation: conv, Messages: msgs, HasOlderMessages: hasOlder}
	if runID, err := q.GetLatestRunningPromptRun(ctx, convID.String()); err == nil {
		det.InFlightRunID = uuid.UUID(runID.Bytes).String()
	}
	if suspendedRun, err := q.GetLatestSuspendedRunByConversation(ctx, convID.String()); err == nil {
		det.PendingConfirmation = parsePendingConfirmation(suspendedRun.Checkpoint)
	}
	return det, nil
}

// parsePendingConfirmation extracts the actionable confirmation card
// from a suspended run's checkpoint, or returns nil when the checkpoint
// doesn't describe one.
func parsePendingConfirmation(checkpointJSON []byte) *PendingConfirmation {
	if len(checkpointJSON) == 0 {
		return nil
	}
	var cp struct {
		SuspensionContext struct {
			Reason           string `json:"reason"`
			PendingToolCalls []struct {
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"pendingToolCalls"`
			Data struct {
				ToolCallID string `json:"toolCallID"`
				Child      struct {
					Confirmation struct {
						Permission string   `json:"permission"`
						Patterns   []string `json:"patterns"`
						Code       string   `json:"code"`
					} `json:"confirmation"`
				} `json:"child"`
			} `json:"data"`
		} `json:"suspensionContext"`
	}
	if err := json.Unmarshal(checkpointJSON, &cp); err != nil {
		return nil
	}
	sc := cp.SuspensionContext
	switch {
	case sc.Reason == "delegated" && sc.Data.Child.Confirmation.Code != "":
		conf := sc.Data.Child.Confirmation
		return &PendingConfirmation{
			ToolCallID: sc.Data.ToolCallID,
			ToolName:   conf.Permission,
			Permission: conf.Permission,
			Patterns:   conf.Patterns,
			Code:       conf.Code,
		}
	case len(sc.PendingToolCalls) > 0:
		pc := sc.PendingToolCalls[0]
		return &PendingConfirmation{
			ToolCallID: pc.ID,
			ToolName:   pc.Name,
			Input:      string(pc.Input),
		}
	}
	return nil
}

// MessagePage is the body of ListMessages — a paginated slice + a
// has-more flag for the chat infinite-scroll.
type MessagePage struct {
	Messages []dbq.AgentMessage
	HasMore  bool
}

// ListMessages returns messages before or after a sequence number for
// infinite scroll. Exactly one of `before` or `after` must be non-empty;
// `limit` is clamped to 1..500 with a default of 100. The caller does
// the owner gate via ownedConversation upstream — this method assumes
// the conversation has already been authorized.
func (s *Service) ListMessages(ctx context.Context, convID uuid.UUID, before, after string, limitParam string) (MessagePage, error) {
	if (before == "") == (after == "") {
		return MessagePage{}, service.Detail(service.ErrInvalidInput, "exactly one of before or after is required")
	}
	limit := int32(100)
	if limitParam != "" {
		if n, err := strconv.Atoi(limitParam); err == nil && n > 0 && n <= 500 {
			limit = int32(n)
		}
	}
	limit++
	q := dbq.New(s.db.Pool())
	var msgs []dbq.AgentMessage
	if before != "" {
		seq, err := strconv.ParseInt(before, 10, 64)
		if err != nil {
			return MessagePage{}, service.Detail(service.ErrInvalidInput, "invalid before seq")
		}
		msgs, err = q.ListMessagesBackward(ctx, dbq.ListMessagesBackwardParams{
			ConversationID: toPg(convID), Before: seq, Lim: limit,
		})
		if err != nil {
			s.logger.Error("list messages backward", zap.Error(err))
			return MessagePage{}, err
		}
	} else {
		seq, err := strconv.ParseInt(after, 10, 64)
		if err != nil {
			return MessagePage{}, service.Detail(service.ErrInvalidInput, "invalid after seq")
		}
		msgs, err = q.ListMessagesForward(ctx, dbq.ListMessagesForwardParams{
			ConversationID: toPg(convID), After: seq, Lim: limit,
		})
		if err != nil {
			s.logger.Error("list messages forward", zap.Error(err))
			return MessagePage{}, err
		}
	}
	hasMore := int32(len(msgs)) >= limit
	if hasMore {
		if before != "" {
			msgs = msgs[1:]
		} else {
			msgs = msgs[:len(msgs)-1]
		}
	}
	return MessagePage{Messages: msgs, HasMore: hasMore}, nil
}

// Delete removes a conversation and schedules S3 cleanup for any
// attachment blobs its messages referenced. Owner + surface gated like
// Get; the S3 cleanup is best-effort.
func (s *Service) Delete(ctx context.Context, userID, convID uuid.UUID) error {
	if userID == uuid.Nil {
		return service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	conv, err := q.GetConversationByID(ctx, toPg(convID))
	if err != nil ||
		!conv.UserID.Valid || uuid.UUID(conv.UserID.Bytes) != userID ||
		conv.Source == "a2a" {
		return service.ErrNotFound
	}
	agentID := convert.PgUUIDToString(conv.AgentID)
	if s.s3 == nil || s.extractKeys == nil {
		// Best-effort cleanup disabled (no s3 client wired) — proceed to row delete.
	} else if rows, listErr := q.ListAllMessagesByConversation(ctx, toPg(convID)); listErr != nil {
		s.logger.Warn("delete conversation cleanup: list messages failed", zap.Error(listErr))
	} else {
		seen := make(map[string]struct{})
		var keys []string
		for _, m := range rows {
			if len(m.Parts) == 0 {
				continue
			}
			for _, k := range s.extractKeys(m.Parts, agentID) {
				if _, dup := seen[k]; dup {
					continue
				}
				seen[k] = struct{}{}
				keys = append(keys, k)
			}
		}
		if len(keys) > 0 {
			attachref.ScheduleDelete(ctx, s.s3, s.logger, keys)
		}
	}
	if err := q.DeleteConversation(ctx, toPg(convID)); err != nil {
		return service.ErrNotFound
	}
	return nil
}

// OwnedConversation enforces the same owner + surface gate as Get /
// Delete and returns the conversation row for the caller to use.
// Centralizes the gate used by the topic endpoints.
func (s *Service) OwnedConversation(ctx context.Context, userID, convID uuid.UUID) (dbq.AgentConversation, error) {
	if userID == uuid.Nil {
		return dbq.AgentConversation{}, service.ErrUnauthorized
	}
	conv, err := dbq.New(s.db.Pool()).GetConversationByID(ctx, toPg(convID))
	if err != nil ||
		!conv.UserID.Valid || uuid.UUID(conv.UserID.Bytes) != userID ||
		conv.Source == "a2a" {
		return dbq.AgentConversation{}, service.ErrNotFound
	}
	return conv, nil
}

// Topic carries one topic + this conversation's subscription state.
type Topic struct {
	ID          uuid.UUID
	Slug        string
	Description string
	Subscribed  bool
}

// ListTopics returns the agent's topics with this conversation's
// subscription flag set. Caller must have already passed the
// OwnedConversation gate.
func (s *Service) ListTopics(ctx context.Context, conv dbq.AgentConversation) ([]Topic, error) {
	q := dbq.New(s.db.Pool())
	topics, err := q.ListTopicsByAgent(ctx, conv.AgentID)
	if err != nil {
		s.logger.Error("list topics", zap.Error(err))
		return nil, err
	}
	subs, err := q.ListTopicSubscriptions(ctx, dbq.ListTopicSubscriptionsParams{
		AgentID: conv.AgentID, ConversationID: conv.ID,
	})
	if err != nil {
		s.logger.Error("list topic subscriptions", zap.Error(err))
		return nil, err
	}
	subscribed := make(map[string]bool, len(subs))
	for _, sub := range subs {
		subscribed[sub.TopicSlug] = true
	}
	out := make([]Topic, len(topics))
	for i, t := range topics {
		out[i] = Topic{
			ID:          uuid.UUID(t.ID.Bytes),
			Slug:        t.Slug,
			Description: t.Description,
			Subscribed:  subscribed[t.Slug],
		}
	}
	return out, nil
}

// SubscribeTopic attaches the conversation to a topic. ErrNotFound for
// an unknown slug. Caller has already passed the OwnedConversation gate.
func (s *Service) SubscribeTopic(ctx context.Context, conv dbq.AgentConversation, slug string) error {
	if slug == "" {
		return service.Detail(service.ErrInvalidInput, "topic slug is required")
	}
	q := dbq.New(s.db.Pool())
	topic, err := q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{AgentID: conv.AgentID, Slug: slug})
	if err != nil {
		return service.ErrNotFound
	}
	if err := q.SubscribeTopic(ctx, dbq.SubscribeTopicParams{TopicID: topic.ID, ConversationID: conv.ID}); err != nil {
		s.logger.Error("subscribe topic", zap.Error(err))
		return err
	}
	return nil
}

// UnsubscribeTopic detaches the conversation from a topic.
func (s *Service) UnsubscribeTopic(ctx context.Context, conv dbq.AgentConversation, slug string) error {
	if slug == "" {
		return service.Detail(service.ErrInvalidInput, "topic slug is required")
	}
	q := dbq.New(s.db.Pool())
	topic, err := q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{AgentID: conv.AgentID, Slug: slug})
	if err != nil {
		return service.ErrNotFound
	}
	if err := q.UnsubscribeTopic(ctx, dbq.UnsubscribeTopicParams{TopicID: topic.ID, ConversationID: conv.ID}); err != nil {
		s.logger.Error("unsubscribe topic", zap.Error(err))
		return err
	}
	return nil
}

var _ = errors.New
