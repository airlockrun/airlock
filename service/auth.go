package service

import (
	"context"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// ResolveAgent looks up an agent by either its UUID or its slug. Used
// by surfaces whose route param is shaped as `{identifier}` — the MCP
// JSON-RPC entry point and the OAuth Authorization Server endpoints.
// External MCP clients can use the rename-safe UUID or a slug. Either form
// resolves to the same row. This is a lookup, not an authorization gate
// — callers gate separately via authz.Authorize / authz.Principal.
func ResolveAgent(ctx context.Context, q *dbq.Queries, identifier string) (dbq.Agent, error) {
	if id, err := uuid.Parse(identifier); err == nil {
		return q.GetAgentByID(ctx, pgtype.UUID{Bytes: id, Valid: true})
	}
	return q.GetAgentBySlug(ctx, identifier)
}
