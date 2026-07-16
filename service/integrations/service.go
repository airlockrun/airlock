// Package integrations provides authenticated development-time access to an
// agent's bound connections, exec endpoints, and MCP servers.
package integrations

import (
	"context"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Backend executes already-authorized operations through Airlock's existing
// credential and SSH brokers.
type Backend interface {
	RequestConnection(context.Context, uuid.UUID, string, wire.ProxyRequest) (ConnectionResult, error)
	RunExec(context.Context, uuid.UUID, string, wire.ExecRequest) (ExecResult, error)
	ListMCPTools(context.Context, uuid.UUID, string) (MCPTools, error)
	CallMCPTool(context.Context, uuid.UUID, string, wire.MCPToolCallRequest) (wire.MCPToolCallResponse, error)
}

type Service struct {
	db      *db.DB
	backend Backend
}

func New(database *db.DB, backend Backend) *Service {
	if database == nil {
		panic("integrations: database is required")
	}
	if backend == nil {
		panic("integrations: backend is required")
	}
	return &Service{db: database, backend: backend}
}

type Info struct {
	Type        string
	Slug        string
	Description string
	Configured  bool
}

type ConnectionResult struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

type ExecResult struct {
	Stdout     []byte
	Stderr     []byte
	ExitCode   int
	DurationMs int64
}

type MCPTools struct {
	Tools        []wire.MCPToolSchema
	Instructions string
}

func (s *Service) List(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]Info, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentIntegrationInvoke, agentID); err != nil {
		return nil, err
	}
	pgAgentID := pgtype.UUID{Bytes: agentID, Valid: true}
	connections, err := q.ListConnectionNeedsByAgent(ctx, pgAgentID)
	if err != nil {
		return nil, err
	}
	mcpServers, err := q.ListMCPNeedsByAgent(ctx, pgAgentID)
	if err != nil {
		return nil, err
	}
	execEndpoints, err := q.ListExecNeedsByAgent(ctx, pgAgentID)
	if err != nil {
		return nil, err
	}

	out := make([]Info, 0, len(connections)+len(mcpServers)+len(execEndpoints))
	for _, c := range connections {
		out = append(out, Info{Type: "connection", Slug: c.Slug, Description: c.Description, Configured: c.Bound && c.Authorized})
	}
	for _, m := range mcpServers {
		configured := m.Bound && (m.AuthMode == string(wire.MCPAuthNone) || m.Authorized)
		out = append(out, Info{Type: "mcp_server", Slug: m.Slug, Description: m.Name, Configured: configured})
	}
	for _, e := range execEndpoints {
		configured := e.Bound && e.Host.Valid && e.SshUser.Valid && e.PublicKeyOpenssh.Valid
		out = append(out, Info{Type: "exec_endpoint", Slug: e.Slug, Description: e.Description, Configured: configured})
	}
	return out, nil
}

func (s *Service) RequestConnection(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string, req wire.ProxyRequest) (ConnectionResult, error) {
	if err := s.authorize(ctx, p, agentID); err != nil {
		return ConnectionResult{}, err
	}
	return s.backend.RequestConnection(ctx, agentID, slug, req)
}

func (s *Service) RunExec(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string, req wire.ExecRequest) (ExecResult, error) {
	if err := s.authorize(ctx, p, agentID); err != nil {
		return ExecResult{}, err
	}
	return s.backend.RunExec(ctx, agentID, slug, req)
}

func (s *Service) ListMCPTools(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) (MCPTools, error) {
	if err := s.authorize(ctx, p, agentID); err != nil {
		return MCPTools{}, err
	}
	return s.backend.ListMCPTools(ctx, agentID, slug)
}

func (s *Service) CallMCPTool(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string, req wire.MCPToolCallRequest) (wire.MCPToolCallResponse, error) {
	if err := s.authorize(ctx, p, agentID); err != nil {
		return wire.MCPToolCallResponse{}, err
	}
	return s.backend.CallMCPTool(ctx, agentID, slug, req)
}

func (s *Service) authorize(ctx context.Context, p authz.Principal, agentID uuid.UUID) error {
	return authz.Authorize(ctx, dbq.New(s.db.Pool()), p, authz.AgentIntegrationInvoke, agentID)
}
