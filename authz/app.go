package authz

import (
	"context"
	"errors"
	"github.com/airlockrun/agentsdk/wire"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// App authority comes only from the middleware credential, never a human role
// or caller-supplied selector. Mutating services retain this lock in their tx.
func authorizeAppRuntime(ctx context.Context, q *dbq.Queries, p Principal, agentID uuid.UUID) error {
	if p.appRunID != uuid.Nil {
		if p.Kind != KindTrigger || p.appRunAgentID != agentID {
			return apperr.ErrForbidden
		}
		live, err := q.IsAdmittedAgentTaskLive(ctx, dbq.IsAdmittedAgentTaskLiveParams{ID: dbqUUID(p.appRunID), AgentID: dbqUUID(agentID), RuntimeProtocol: wire.AppRuntimeProtocol})
		if err != nil {
			return err
		}
		if !live {
			return apperr.ErrUnauthorized
		}
		return nil
	}
	id := auth.AgentIDFromContext(ctx)
	generation := auth.AgentTokenVersionFromContext(ctx)
	if id == uuid.Nil || generation < 1 {
		return apperr.ErrUnauthorized
	}
	if p.Kind != KindTrigger || id != agentID {
		return apperr.ErrForbidden
	}
	app, err := q.GetAgentByIDForUpdate(ctx, dbqUUID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.ErrUnauthorized
	}
	if err != nil {
		return err
	}
	if app.AgentTokenVersion != generation || app.Status != "active" && app.Status != "building" {
		return apperr.ErrUnauthorized
	}
	return nil
}

// AppRunPrincipal restores only an exact, leased application-owned task. A plain
// trigger principal still requires an inbound app credential for app operations.
func AppRunPrincipal(ctx context.Context, q *dbq.Queries, agentID, runID uuid.UUID) (Principal, error) {
	if agentID == uuid.Nil || runID == uuid.Nil {
		return Principal{}, apperr.ErrUnauthorized
	}
	p := Principal{Kind: KindTrigger, appRunAgentID: agentID, appRunID: runID}
	if err := Authorize(ctx, q, p, AppRuntime, agentID); err != nil {
		return Principal{}, err
	}
	return p, nil
}
