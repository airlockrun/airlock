package systemchat

import (
	"context"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

func (s *Service) AppendNotification(ctx context.Context, agentID, conversationID, originRunID uuid.UUID, source, content string) (dbq.SystemConversation, error) {
	p, err := s.ResumePrincipal(ctx, conversationID, originRunID)
	if err != nil {
		return dbq.SystemConversation{}, err
	}
	conversation, err := s.GetConversation(ctx, p, conversationID)
	if err != nil {
		return dbq.SystemConversation{}, err
	}
	q := dbq.New(s.db.Pool())
	if agentID != uuid.Nil {
		if err := authz.Authorize(ctx, q, p, authz.AgentBuildsView, agentID); err != nil {
			return dbq.SystemConversation{}, err
		}
	}
	_, err = q.AppendSystemMessage(ctx, dbq.AppendSystemMessageParams{ConversationID: conversation.Conversation.ID, Role: "user", Source: source, Content: content, CostEstimate: pgNumericFromFloat(0)})
	if err != nil {
		return dbq.SystemConversation{}, err
	}
	if err := q.TouchSystemConversation(ctx, conversation.Conversation.ID); err != nil {
		return dbq.SystemConversation{}, err
	}
	return conversation.Conversation, nil
}
