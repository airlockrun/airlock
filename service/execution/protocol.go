package execution

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
)

// RequireRuntimeProtocol fences admission against the current generation's
// complete synchronized app manifest, independently of SDK semver.
func RequireRuntimeProtocol(ctx context.Context, q *dbq.Queries, agentID uuid.UUID) error {
	manifest, err := q.GetRuntimeManifest(ctx, pgID(agentID))
	if err != nil {
		return service.Detail(service.ErrConflict, "app manifest is unavailable; rebuild the app")
	}
	var value wire.AgentManifest
	if err := json.Unmarshal(manifest, &value); err != nil {
		return service.Detail(service.ErrConflict, "invalid app manifest; rebuild the app")
	}
	if err := wire.CheckAppRuntimeProtocol(value.RuntimeProtocol); err != nil {
		return service.Detail(service.ErrConflict, "%s", err)
	}
	return nil
}
