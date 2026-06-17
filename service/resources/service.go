// Package resources owns the per-user, owner-scoped view of the sluggable
// proxy resources (connections, MCP servers, exec endpoints): the list of
// resources a principal owns, across all of their agents, with how many agents
// currently bind each one. It is read-only — resources are created and
// credentialed from an agent's needs (see service/needs); this surface is the
// owner's inventory, the connection/exec analogue of the git-credentials list.
package resources

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Resource is the wire shape for one owned resource. No secret material is
// carried — only what the owner inventory renders.
type Resource struct {
	ID         uuid.UUID
	Type       string // connection | mcp_server | exec_endpoint
	Slug       string
	Name       string
	AuthMode   string
	Authorized bool
	AgentCount int32
	CreatedAt  pgtype.Timestamptz
	LastUsedAt pgtype.Timestamptz
}

type Service struct {
	db     *db.DB
	logger *zap.Logger
}

func New(d *db.DB, logger *zap.Logger) *Service {
	if d == nil {
		panic("resources: db is required")
	}
	if logger == nil {
		panic("resources: logger is required")
	}
	return &Service{db: d, logger: logger}
}

// List returns every connection / MCP server / exec endpoint owned by the
// caller's grantee set, with the agent-bind count for each. Self-scoped: the
// owner filter is the caller's own grantee set, so there is no cross-owner
// exposure and no agent-axis gate.
func (s *Service) List(ctx context.Context, p authz.Principal) ([]Resource, error) {
	if !p.IsAuthenticatedUser() {
		return nil, service.ErrUnauthorized
	}
	owners := ownerSet(p)
	q := dbq.New(s.db.Pool())

	conns, err := q.ListOwnedConnections(ctx, owners)
	if err != nil {
		s.logger.Error("list owned connections failed", zap.Error(err))
		return nil, err
	}
	mcps, err := q.ListOwnedMCPServers(ctx, owners)
	if err != nil {
		s.logger.Error("list owned MCP servers failed", zap.Error(err))
		return nil, err
	}
	execs, err := q.ListOwnedExecEndpoints(ctx, owners)
	if err != nil {
		s.logger.Error("list owned exec endpoints failed", zap.Error(err))
		return nil, err
	}

	out := make([]Resource, 0, len(conns)+len(mcps)+len(execs))
	for _, c := range conns {
		out = append(out, Resource{
			ID: uuid.UUID(c.ID.Bytes), Type: "connection", Slug: c.Slug, Name: c.Name,
			AuthMode: c.AuthMode, Authorized: c.Authorized, AgentCount: c.AgentCount, CreatedAt: c.CreatedAt,
		})
	}
	for _, m := range mcps {
		out = append(out, Resource{
			ID: uuid.UUID(m.ID.Bytes), Type: "mcp_server", Slug: m.Slug, Name: m.Name,
			AuthMode: m.AuthMode, Authorized: m.Authorized, AgentCount: m.AgentCount, CreatedAt: m.CreatedAt,
		})
	}
	for _, e := range execs {
		out = append(out, Resource{
			ID: uuid.UUID(e.ID.Bytes), Type: "exec_endpoint", Slug: e.Slug, Name: e.Slug,
			Authorized: e.Configured, AgentCount: e.AgentCount, CreatedAt: e.CreatedAt, LastUsedAt: e.LastUsedAt,
		})
	}
	return out, nil
}

// ownerSet maps the caller's grantee set to the owner_principal_id filter. In
// OSS resources are user-owned, so this is effectively the caller's user id;
// the grantee set keeps it forward-compatible with group ownership.
func ownerSet(p authz.Principal) []pgtype.UUID {
	set := p.GranteeSet()
	out := make([]pgtype.UUID, len(set))
	for i, id := range set {
		out[i] = pgtype.UUID{Bytes: id, Valid: true}
	}
	return out
}
