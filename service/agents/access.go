package agents

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AccessSettings controls external MCP and anonymous HTTP exposure.
type AccessSettings struct {
	McpEnabled        bool
	AllowPublicMcp    bool
	AllowPublicRoutes bool
}

func (s *Service) GetAccessSettings(ctx context.Context, p authz.Principal, agentID uuid.UUID) (AccessSettings, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentMembersManage, agentID); err != nil {
		return AccessSettings{}, err
	}
	a, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return AccessSettings{}, err
	}
	return AccessSettings{McpEnabled: a.McpEnabled, AllowPublicMcp: a.AllowPublicMcp, AllowPublicRoutes: a.AllowPublicRoutes}, nil
}

func (s *Service) UpdateAccessSettings(ctx context.Context, p authz.Principal, agentID uuid.UUID, in AccessSettings) (AccessSettings, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentMembersManage, agentID); err != nil {
		return AccessSettings{}, err
	}
	if !in.McpEnabled {
		in.AllowPublicMcp = false
	}
	err := q.UpdateAgentAccessSettings(ctx, dbq.UpdateAgentAccessSettingsParams{ID: pgtype.UUID{Bytes: agentID, Valid: true}, McpEnabled: in.McpEnabled, AllowPublicMcp: in.AllowPublicMcp, AllowPublicRoutes: in.AllowPublicRoutes})
	return in, err
}
