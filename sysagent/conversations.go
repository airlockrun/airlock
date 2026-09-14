package sysagent

import (
	"context"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/systemchat"
	"github.com/google/uuid"
	"time"
)

type ConversationDetail = systemchat.ConversationDetail
type RunSummary = systemchat.RunSummary
type ListRunsResult = systemchat.ListRunsResult

func (s *Service) ListConversations(ctx context.Context, p authz.Principal) ([]dbq.SystemConversation, error) {
	return s.domain.ListConversations(ctx, p)
}
func (s *Service) CreateConversation(ctx context.Context, p authz.Principal, title string) (dbq.SystemConversation, error) {
	return s.domain.CreateConversation(ctx, p, title)
}

func (s *Service) EnsureBridgeConversation(ctx context.Context, p authz.Principal) (dbq.SystemConversation, error) {
	return s.domain.EnsureBridgeConversation(ctx, p)
}
func (s *Service) GetConversation(ctx context.Context, p authz.Principal, id uuid.UUID) (ConversationDetail, error) {
	return s.domain.GetConversation(ctx, p, id)
}
func (s *Service) DeleteConversation(ctx context.Context, p authz.Principal, id uuid.UUID) error {
	return s.domain.DeleteConversation(ctx, p, id)
}
func (s *Service) ListRuns(ctx context.Context, p authz.Principal, cursor time.Time, limit int32) (ListRunsResult, error) {
	return s.domain.ListRuns(ctx, p, cursor, limit)
}
