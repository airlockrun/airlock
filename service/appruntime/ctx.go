package appruntime

import (
	"context"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/google/uuid"
)

// ResolveRun is the remote app callback gate. Native app-wide operations do not
// call it unless they associate their effects with an admitted run.
func (h *Service) ResolveRun(ctx context.Context, runID uuid.UUID) (execution.Context, error) {
	q := dbq.New(h.db.Pool())
	appID, err := h.admit(ctx, q)
	if err != nil {
		return execution.Context{}, err
	}
	return execution.ResolveInvocation(ctx, q, appID, runID, auth.AgentTokenVersionFromContext(ctx), execution.InvocationProofFromContext(ctx))
}
