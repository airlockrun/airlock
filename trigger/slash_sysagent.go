package trigger

import (
	"context"
	"errors"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/systemchat"
	"github.com/airlockrun/sol/eventstream"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// SysagentRuntime keeps the runtime orchestrator outside trigger's import graph.
type SysagentRuntime interface {
	CancelRun(context.Context, authz.Principal, uuid.UUID) (bool, error)
	ControlConversation(context.Context, authz.Principal, uuid.UUID, string, string) (bool, error)
	Compact(context.Context, authz.Principal, uuid.UUID) (string, error)
	NotifyBotCreated(context.Context, uuid.UUID, uuid.UUID, string) error
	ResumePrincipal(context.Context, uuid.UUID, uuid.UUID) (authz.Principal, error)
	EnsureBridgeConversation(context.Context, authz.Principal) (dbq.SystemConversation, error)
	GetConversation(context.Context, authz.Principal, uuid.UUID) (systemchat.ConversationDetail, error)
	RunPromptInline(context.Context, authz.Principal, uuid.UUID, string, string, *bool, string, eventstream.Sink, func(uuid.UUID)) (uuid.UUID, error)
}

type SysagentSlashConv struct {
	svc    SysagentRuntime
	p      authz.Principal
	logger *zap.Logger
}

func NewSysagentSlashConv(svc SysagentRuntime, p authz.Principal, logger *zap.Logger) *SysagentSlashConv {
	if svc == nil || logger == nil {
		panic("trigger: system slash dependencies required")
	}
	return &SysagentSlashConv{svc: svc, p: p, logger: logger}
}

func (s *SysagentSlashConv) Cancel(ctx context.Context, id pgtype.UUID) bool {
	if !id.Valid {
		return false
	}
	changed, err := s.svc.ControlConversation(ctx, s.p, uuid.UUID(id.Bytes), "cancel", "")
	if err != nil {
		s.logger.Warn("system cancellation rejected", zap.Error(err))
		return false
	}
	return changed
}
func (s *SysagentSlashConv) Clear(ctx context.Context, id pgtype.UUID) (bool, error) {
	if !id.Valid {
		return false, errors.New("no conversation")
	}
	return s.svc.ControlConversation(ctx, s.p, uuid.UUID(id.Bytes), "clear", "")
}
func (s *SysagentSlashConv) Compact(ctx context.Context, id pgtype.UUID) (string, bool, error) {
	if !id.Valid {
		return "", false, errors.New("no conversation")
	}
	summary, err := s.svc.Compact(ctx, s.p, uuid.UUID(id.Bytes))
	return summary, false, err
}
func (s *SysagentSlashConv) Echo(ctx context.Context, id pgtype.UUID, args string) (bool, error) {
	if !id.Valid {
		return false, errors.New("no conversation")
	}
	return s.svc.ControlConversation(ctx, s.p, uuid.UUID(id.Bytes), "echo", args)
}
func (s *SysagentSlashConv) Start(context.Context, pgtype.UUID) string {
	return "Hi! I'm your Airlock assistant. Ask me to manage agents, bots, connections, models, and more."
}
