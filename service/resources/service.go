// Package resources owns the per-user inventory and management surface for
// reusable connections, MCP servers, and exec endpoints.
package resources

import (
	"context"
	"strings"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Resource is one resource available to the caller through ownership or a
// grant. It carries no secret material.
type Resource struct {
	ID           uuid.UUID
	Type         string // connection | mcp_server | exec_endpoint
	Slug         string
	Name         string
	DisplayName  string
	AuthMode     string
	Authorized   bool
	AgentCount   int32
	Capabilities []string
	CreatedAt    pgtype.Timestamptz
	LastUsedAt   pgtype.Timestamptz
}

// Consumer identifies an agent need bound to a resource.
type Consumer struct {
	AgentID        uuid.UUID
	AgentName      string
	AgentSlug      string
	NeedType       string
	NeedSlug       string
	CanAccessAgent bool
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

// List returns resources available through ownership or a resource grant and
// exposes the caller's capabilities on each one.
func (s *Service) List(ctx context.Context, p authz.Principal) ([]Resource, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.ResourceInventoryView, uuid.Nil); err != nil {
		return nil, err
	}
	principals := principalSet(p)
	conns, err := q.ListAvailableConnections(ctx, principals)
	if err != nil {
		s.logger.Error("list available connections failed", zap.Error(err))
		return nil, err
	}
	mcps, err := q.ListAvailableMCPServers(ctx, principals)
	if err != nil {
		s.logger.Error("list available MCP servers failed", zap.Error(err))
		return nil, err
	}
	execs, err := q.ListAvailableExecEndpoints(ctx, principals)
	if err != nil {
		s.logger.Error("list available exec endpoints failed", zap.Error(err))
		return nil, err
	}

	out := make([]Resource, 0, len(conns)+len(mcps)+len(execs))
	for _, c := range conns {
		out = append(out, Resource{
			ID: uuid.UUID(c.ID.Bytes), Type: "connection", Slug: c.Slug, Name: c.Name, DisplayName: c.DisplayName,
			AuthMode: c.AuthMode, Authorized: c.Authorized, AgentCount: c.AgentCount, Capabilities: c.Capabilities, CreatedAt: c.CreatedAt,
		})
	}
	for _, m := range mcps {
		out = append(out, Resource{
			ID: uuid.UUID(m.ID.Bytes), Type: "mcp_server", Slug: m.Slug, Name: m.Name, DisplayName: m.DisplayName,
			AuthMode: m.AuthMode, Authorized: m.Authorized, AgentCount: m.AgentCount, Capabilities: m.Capabilities, CreatedAt: m.CreatedAt,
		})
	}
	for _, e := range execs {
		out = append(out, Resource{
			ID: uuid.UUID(e.ID.Bytes), Type: "exec_endpoint", Slug: e.Slug, Name: e.Slug, DisplayName: e.DisplayName,
			Authorized: e.Configured, AgentCount: e.AgentCount, Capabilities: e.Capabilities, CreatedAt: e.CreatedAt, LastUsedAt: e.LastUsedAt,
		})
	}
	return out, nil
}

func principalSet(p authz.Principal) []pgtype.UUID {
	set := p.GranteeSet()
	out := make([]pgtype.UUID, len(set))
	for i, id := range set {
		out[i] = pgtype.UUID{Bytes: id, Valid: true}
	}
	return out
}

// Consumers lists every agent need bound to a resource. Resource view
// capability is required; agent membership is not, because the grant controls
// visibility of this resource-level relationship.
func (s *Service) Consumers(ctx context.Context, p authz.Principal, typ string, id uuid.UUID) ([]Consumer, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceView, typ, id); err != nil {
		return nil, err
	}
	pgID := pgtype.UUID{Bytes: id, Valid: true}
	var out []Consumer
	switch typ {
	case "connection":
		rows, err := q.ListConnectionConsumers(ctx, pgID)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			canAccess := authz.Authorize(ctx, q, p, authz.AgentGet, uuid.UUID(row.AgentID.Bytes)) == nil
			out = append(out, Consumer{uuid.UUID(row.AgentID.Bytes), row.AgentName, row.AgentSlug, row.NeedType, row.NeedSlug, canAccess})
		}
	case "mcp_server":
		rows, err := q.ListMCPServerConsumers(ctx, pgID)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			canAccess := authz.Authorize(ctx, q, p, authz.AgentGet, uuid.UUID(row.AgentID.Bytes)) == nil
			out = append(out, Consumer{uuid.UUID(row.AgentID.Bytes), row.AgentName, row.AgentSlug, row.NeedType, row.NeedSlug, canAccess})
		}
	case "exec_endpoint":
		rows, err := q.ListExecEndpointConsumers(ctx, pgID)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			canAccess := authz.Authorize(ctx, q, p, authz.AgentGet, uuid.UUID(row.AgentID.Bytes)) == nil
			out = append(out, Consumer{uuid.UUID(row.AgentID.Bytes), row.AgentName, row.AgentSlug, row.NeedType, row.NeedSlug, canAccess})
		}
	default:
		return nil, service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	return out, nil
}

// Rename updates a resource's non-unique user-controlled display name.
func (s *Service) Rename(ctx context.Context, p authz.Principal, typ string, id uuid.UUID, displayName string) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, id); err != nil {
		return err
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return service.Detail(service.ErrInvalidInput, "display name is required")
	}
	pgID := pgtype.UUID{Bytes: id, Valid: true}
	var affected int64
	switch typ {
	case "connection":
		affected, err = q.RenameConnection(ctx, dbq.RenameConnectionParams{ID: pgID, DisplayName: displayName})
	case "mcp_server":
		affected, err = q.RenameMCPServer(ctx, dbq.RenameMCPServerParams{ID: pgID, DisplayName: displayName})
	case "exec_endpoint":
		affected, err = q.RenameExecEndpoint(ctx, dbq.RenameExecEndpointParams{ID: pgID, DisplayName: displayName})
	default:
		return service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	return tx.Commit(ctx)
}

// Revoke clears stored credentials. Resource manage capability is required.
func (s *Service) Revoke(ctx context.Context, p authz.Principal, typ string, id uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, id); err != nil {
		return err
	}
	pgID := pgtype.UUID{Bytes: id, Valid: true}
	var affected int64
	switch typ {
	case "connection":
		affected, err = q.ClearConnectionCredentialsByID(ctx, pgID)
	case "mcp_server":
		affected, err = q.ClearMCPServerCredentialsByID(ctx, pgID)
	default:
		return service.Detail(service.ErrInvalidInput, "%s resources have no credentials to revoke", typ)
	}
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	return tx.Commit(ctx)
}

// Delete removes a resource. Grants cascade and bound needs become unbound.
func (s *Service) Delete(ctx context.Context, p authz.Principal, typ string, id uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, id); err != nil {
		return err
	}
	pgID := pgtype.UUID{Bytes: id, Valid: true}
	switch typ {
	case "connection":
		if _, err := q.LockConnectionBindings(ctx, pgID); err != nil {
			return err
		}
	case "mcp_server":
		if _, err := q.LockMCPBindings(ctx, pgID); err != nil {
			return err
		}
	case "exec_endpoint":
		if _, err := q.LockExecBindings(ctx, pgID); err != nil {
			return err
		}
	default:
		return service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	if err := authz.LockResource(ctx, q, typ, id); err != nil {
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, id); err != nil {
		return err
	}
	var affected int64
	switch typ {
	case "connection":
		affected, err = q.DeleteConnectionByID(ctx, pgID)
	case "mcp_server":
		affected, err = q.DeleteMCPServerByID(ctx, pgID)
	case "exec_endpoint":
		affected, err = q.DeleteExecEndpointByID(ctx, pgID)
	}
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	return tx.Commit(ctx)
}
