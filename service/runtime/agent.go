package runtime

import (
	"context"
	"strings"

	"github.com/airlockrun/agentsdk/agentruntime"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/capabilities"
	"github.com/airlockrun/airlock/service/chatruns"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func (h *Service) PrepareAgent(ctx context.Context, scope capabilities.Scope, d wire.AgentDefinition) (agentruntime.Input, error) {
	var in agentruntime.Input
	admitted, err := execution.Resolve(ctx, dbq.New(h.db.Pool()), scope.AgentID, scope.RunID)
	if err != nil {
		return in, err
	}
	model, err := h.RuntimeModel(ctx, scope.AgentID, scope.RunID, d.ModelSlot, "text")
	if err != nil {
		return in, err
	}
	resolved := model.(*runtimeModel)
	// The task controller and outer model supervisor own primary reasoning and
	// compaction accounting; native callback models account through runtimeModel.
	resolved.budgetManaged = true
	if err := resolved.resolved.Limits.Validate(true); err != nil {
		return in, err
	}
	in.Model, in.ModelLimits = model, resolved.resolved.Limits
	in.Redactor = func(text string) string {
		if resolved.resolved.ApiKey != "" {
			return strings.ReplaceAll(text, resolved.resolved.ApiKey, "[REDACTED]")
		}
		return text
	}
	in.Store = chatruns.NewAgentSession(h.db, h.s3, scope.AgentID, uuid.UUID(admitted.Run.CallerConversationID.Bytes), scope.RunID, scope.OwnerToken, chatruns.SessionCodec{
		Normalize: func(id pgtype.UUID, rows []dbq.AgentMessage) ([]dbq.AgentMessage, error) {
			normalized, _, _, err := NormalizeToolOrdering(id, rows)
			return normalized, err
		},
		Decode: DbMessageToSession, Store: StoreSessionMessageReturningID, Cleanup: h.CleanupOrphanedAttachments,
	})
	return in, nil
}
