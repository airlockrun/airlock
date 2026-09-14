package jobs

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

// AuthorizeSubscription applies the same gate as the jobs inventory, because
// progress and lifecycle events span every user's jobs for this app.
func AuthorizeSubscription(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID) error {
	return authz.Authorize(ctx, q, p, authz.AgentJobView, agentID)
}
