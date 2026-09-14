package runtime

import (
	"context"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/google/uuid"
)

func (h *Service) admittedContext(ctx context.Context, supplied wire.RuntimeContext) (wire.RuntimeContext, error) {
	agentID, err := uuid.Parse(supplied.AgentID)
	if err != nil {
		return wire.RuntimeContext{}, err
	}
	runID, err := uuid.Parse(supplied.RunID)
	if err != nil {
		return wire.RuntimeContext{}, err
	}
	admitted, err := execution.Resolve(ctx, dbq.New(h.db.Pool()), agentID, runID)
	return admitted.Runtime, err
}
