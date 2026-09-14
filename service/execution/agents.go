package execution

import (
	"context"
	"encoding/json"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AdmitAgentTx binds a task to an app-owned conversation inside the scheduler's
// admission transaction. The task record and origin must commit together.
func AdmitAgentTx(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, generation int64, conversationID uuid.UUID, definition string, input json.RawMessage) (dbq.Run, error) {
	if !json.Valid(input) || definition == "" {
		return dbq.Run{}, service.ErrInvalidInput
	}
	app, err := q.GetAgentByIDForUpdate(ctx, pgID(agentID))
	if err != nil {
		return dbq.Run{}, err
	}
	if app.AgentTokenVersion != generation || generation <= 0 || app.Status != "active" && app.Status != "building" {
		return dbq.Run{}, service.ErrUnauthorized
	}
	if err := RequireRuntimeProtocol(ctx, q, agentID); err != nil {
		return dbq.Run{}, err
	}
	conv, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{ID: pgID(conversationID), AgentID: app.ID})
	if err != nil {
		return dbq.Run{}, err
	}
	if conv.Source != "application" || conv.UserID.Valid || conv.BridgeID.Valid {
		return dbq.Run{}, service.ErrForbidden
	}
	origin, err := q.CreateExecutionOrigin(ctx, dbq.CreateExecutionOriginParams{ID: pgID(uuid.New()), AgentID: app.ID, ConversationID: conv.ID, Ingress: "app", Actor: "app", CredentialProfile: "none", RuntimeGeneration: pgtype.Int8{Int64: generation, Valid: true}})
	if err != nil {
		return dbq.Run{}, err
	}
	return q.CreateRun(ctx, dbq.CreateRunParams{AgentID: app.ID, OriginID: origin.ID, ExecutionKind: string(Agent), TriggerType: "agent", TriggerRef: definition, SourceRef: app.SourceRef, InputPayload: input, CallerAccess: "admin", CallerConversationID: conv.ID})
}
