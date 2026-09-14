package agents

import (
	"context"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func AuthorizeBuildSubscription(ctx context.Context, q *dbq.Queries, p authz.Principal, buildID uuid.UUID) error {
	build, err := q.GetAgentBuild(ctx, pgtype.UUID{Bytes: buildID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	return authz.Authorize(ctx, q, p, authz.AgentBuildsView, uuid.UUID(build.AgentID.Bytes))
}
