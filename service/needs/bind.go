package needs

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Service exposes the operator-facing need lifecycle: create a resource for a
// need, bind an existing one, and list compatible candidates.
type Service struct {
	db      *db.DB
	refresh func(context.Context, uuid.UUID) error
	logger  *zap.Logger
}

func NewService(database *db.DB, refresh func(context.Context, uuid.UUID) error, logger *zap.Logger) *Service {
	if database == nil || refresh == nil || logger == nil {
		panic("needs: nil dependency")
	}
	return &Service{db: database, refresh: refresh, logger: logger}
}

// Candidate is a shape-compatible resource the caller may bind through
// ownership or a resource grant.
type Candidate struct {
	ResourceID   uuid.UUID
	Name         string
	DisplayName  string
	Slug         string
	Readiness    string
	Authorized   bool
	Configured   bool
	AgentCount   int32
	Required     []string
	Missing      []string
	Capabilities []string
}

// NeedInfo is one of an agent's declared needs and whether it's bound yet.
type NeedInfo struct {
	Type            string
	Slug            string
	Description     string
	Bound           bool
	BoundResourceID uuid.UUID
}

// ListNeeds returns the agent's declared resource needs and their binding
// status — the UI's entry point for wiring resources up. Member-readable.
func (s *Service) ListNeeds(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]NeedInfo, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentGet, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListResourceNeedsByAgent(ctx, pg(agentID))
	if err != nil {
		return nil, err
	}
	out := make([]NeedInfo, len(rows))
	for i, n := range rows {
		info := NeedInfo{Type: n.Type, Slug: n.Slug, Description: n.Description}
		switch {
		case n.BoundConnectionID.Valid:
			info.Bound, info.BoundResourceID = true, uuid.UUID(n.BoundConnectionID.Bytes)
		case n.BoundMcpID.Valid:
			info.Bound, info.BoundResourceID = true, uuid.UUID(n.BoundMcpID.Bytes)
		case n.BoundExecID.Valid:
			info.Bound, info.BoundResourceID = true, uuid.UUID(n.BoundExecID.Bytes)
		}
		out[i] = info
	}
	return out, nil
}

// manageAction is the agent-axis gate for managing a resource type.
func manageAction(typ string) authz.Action {
	if typ == "exec_endpoint" {
		return authz.AgentExecEndpoints
	}
	return authz.AgentConnections
}

// jsonEqual compares two JSON blobs structurally — key order and whitespace
// agnostic — so two auth_injection configs that mean the same thing match.
func jsonEqual(a, b []byte) bool {
	if len(a) == 0 {
		a = []byte("{}")
	}
	if len(b) == 0 {
		b = []byte("{}")
	}
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// connSpec / mcpSpec carry the matchable shape pulled from a need's spec.
type connSpec struct {
	BaseURL       string          `json:"base_url"`
	AuthMode      string          `json:"auth_mode"`
	Scopes        string          `json:"scopes"`
	AuthInjection json.RawMessage `json:"auth_injection"`
	AuthParams    json.RawMessage `json:"auth_params"`
	Headers       json.RawMessage `json:"headers"`
}

type mcpSpec struct {
	URL           string          `json:"url"`
	AuthMode      string          `json:"auth_mode"`
	Scopes        string          `json:"scopes"`
	AuthInjection json.RawMessage `json:"auth_injection"`
}

// matchesConnection / matchesMCP are the full-shape compatibility predicates: a
// candidate must agree with the need on url, auth mode, and the auth injection /
// params / headers (the agent's code builds requests assuming that shape), and
// carry at least the requested scopes. URL alone is not enough.
func matchesConnection(needSpec []byte, c dbq.Connection) bool {
	var s connSpec
	_ = json.Unmarshal(needSpec, &s)
	return s.BaseURL == c.BaseUrl &&
		s.AuthMode == c.AuthMode &&
		jsonEqual(s.AuthInjection, c.AuthInjection) &&
		jsonEqual(s.AuthParams, c.AuthParams) &&
		jsonEqual(s.Headers, c.Headers)
}

func matchesMCP(needSpec []byte, m dbq.AgentMcpServer) bool {
	var s mcpSpec
	_ = json.Unmarshal(needSpec, &s)
	return s.URL == m.Url &&
		s.AuthMode == m.AuthMode &&
		jsonEqual(s.AuthInjection, m.AuthInjection)
}

// ConnectionCompatible reports structural compatibility without considering
// OAuth scope readiness.
func ConnectionCompatible(needSpec []byte, connection dbq.Connection) bool {
	return matchesConnection(needSpec, connection)
}

// MCPCompatible reports structural compatibility without considering OAuth
// scope readiness.
func MCPCompatible(needSpec []byte, server dbq.AgentMcpServer) bool {
	return matchesMCP(needSpec, server)
}

func (s *Service) granteeOwners(p authz.Principal) []pgtype.UUID {
	set := p.GranteeSet()
	out := make([]pgtype.UUID, len(set))
	for i, id := range set {
		out[i] = pg(id)
	}
	return out
}

// CreateResourceForNeed instantiates a new resource for the need, owned by the
// caller, and binds it. Agent-admin gated.
func (s *Service) CreateResourceForNeed(ctx context.Context, p authz.Principal, agentID uuid.UUID, typ, slug, displayName string) (uuid.UUID, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(agentID)); err != nil {
		return uuid.Nil, notFoundOr(err)
	}
	if err := authz.Authorize(ctx, q, p, manageAction(typ), agentID); err != nil {
		return uuid.Nil, err
	}
	if typ == "mcp_server" {
		need, err := q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams{AgentID: pg(agentID), Type: typ, Slug: slug})
		if err != nil {
			return uuid.Nil, notFoundOr(err)
		}
		var spec mcpSpec
		_ = json.Unmarshal(need.Spec, &spec)
		if spec.AuthMode == "none" {
			return uuid.Nil, service.Detail(service.ErrInvalidInput, "no-auth MCP resources cannot be created without tool discovery; bind an existing discovered server")
		}
	}
	id, err := CreateForNeed(ctx, q, p, agentID, typ, slug, displayName, true)
	if err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	if typ == "mcp_server" {
		s.refreshAfterMCPChange(ctx, agentID)
	}
	return id, nil
}

// ListCandidates returns the caller's resources (owned by its grantee set) whose
// frozen shape matches the need — the resources it can bind for reuse.
func (s *Service) ListCandidates(ctx context.Context, p authz.Principal, agentID uuid.UUID, typ, slug string) ([]Candidate, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, manageAction(typ), agentID); err != nil {
		return nil, err
	}
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: typ, Slug: slug})
	if err != nil {
		return nil, service.Detail(service.ErrNotFound, "resource %q not declared by the agent", slug)
	}
	principals := s.granteeOwners(p)
	var out []Candidate
	build := func(id uuid.UUID, name, displayName, resourceSlug, authMode, granted string, scopesVerified, hasCredentials bool, count int32) (Candidate, error) {
		capabilities, err := authz.ResourceCapabilities(ctx, q, p, typ, id)
		if err != nil {
			return Candidate{}, err
		}
		required := oauth.Scopes(need.ExpectedScopes)
		missing := oauth.MissingScopes(need.ExpectedScopes, granted)
		configured := authMode == "none" || hasCredentials
		candidate := Candidate{
			ResourceID: id, Name: name, DisplayName: displayName, Slug: resourceSlug,
			Authorized: configured, Configured: configured, Required: required, Missing: missing,
			AgentCount: count, Capabilities: capabilities, Readiness: "ready",
		}
		if (authMode == "oauth" || authMode == "oauth_discovery") && (!scopesVerified || len(missing) > 0) {
			candidate.Readiness = "scope_upgrade_required"
			if !contains(capabilities, authz.CapManage) {
				candidate.Readiness = "scope_upgrade_requires_manager"
			}
		} else if !configured {
			candidate.Readiness = "authorization_required"
		}
		return candidate, nil
	}
	switch typ {
	case "connection":
		rows, err := q.ListConnectionsAvailableToPrincipal(ctx, principals)
		if err != nil {
			return nil, err
		}
		for _, c := range rows {
			if matchesConnection(need.Spec, c) {
				consumers, err := q.ListConnectionConsumers(ctx, c.ID)
				if err != nil {
					return nil, err
				}
				candidate, err := build(uuid.UUID(c.ID.Bytes), c.Name, c.DisplayName, c.Slug, c.AuthMode, c.GrantedScopes, c.ScopesVerified, c.AccessTokenRef != "", int32(len(consumers)))
				if err != nil {
					return nil, err
				}
				out = append(out, candidate)
			}
		}
	case "mcp_server":
		rows, err := q.ListMCPServersAvailableToPrincipal(ctx, principals)
		if err != nil {
			return nil, err
		}
		for _, m := range rows {
			if matchesMCP(need.Spec, m) {
				consumers, err := q.ListMCPServerConsumers(ctx, m.ID)
				if err != nil {
					return nil, err
				}
				candidate, err := build(uuid.UUID(m.ID.Bytes), m.Name, m.DisplayName, m.Slug, m.AuthMode, m.GrantedScopes, m.ScopesVerified, m.AccessTokenRef != "", int32(len(consumers)))
				if err != nil {
					return nil, err
				}
				out = append(out, candidate)
			}
		}
	case "exec_endpoint":
		rows, err := q.ListExecEndpointsAvailableToPrincipal(ctx, principals)
		if err != nil {
			return nil, err
		}
		for _, e := range rows {
			consumers, err := q.ListExecEndpointConsumers(ctx, e.ID)
			if err != nil {
				return nil, err
			}
			candidate, err := build(uuid.UUID(e.ID.Bytes), e.Slug, e.DisplayName, e.Slug, "", "", true, e.Transport.Valid, int32(len(consumers)))
			if err != nil {
				return nil, err
			}
			out = append(out, candidate)
		}
	default:
		return nil, service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	return out, nil
}

// BindExisting binds an existing resource after checking agent admin, resource
// bind capability, and shape compatibility in one transaction.
func (s *Service) BindExisting(ctx context.Context, p authz.Principal, agentID uuid.UUID, typ, slug string, resourceID uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(agentID)); err != nil {
		return notFoundOr(err)
	}
	if err := authz.Authorize(ctx, q, p, manageAction(typ), agentID); err != nil {
		return err
	}
	need, err := q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams{AgentID: pg(agentID), Type: typ, Slug: slug})
	if err != nil {
		return service.Detail(service.ErrNotFound, "resource %q not declared by the agent", slug)
	}
	var affected int64
	switch typ {
	case "connection":
		c, err := q.GetConnectionByIDForUpdate(ctx, pg(resourceID))
		if err != nil {
			return notFoundOr(err)
		}
		if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, typ, resourceID); err != nil {
			return err
		}
		if !matchesConnection(need.Spec, c) {
			return service.Detail(service.ErrInvalidInput, "connection shape does not match the need")
		}
		if c.AuthMode == "oauth" && (!c.ScopesVerified || !oauth.CoversScopes(need.ExpectedScopes, c.GrantedScopes)) {
			return service.Detail(service.ErrConflict, "connection requires OAuth scope authorization before binding")
		}
		if c.AuthMode == "oauth" && c.AccessTokenRef == "" {
			return service.Detail(service.ErrConflict, "connection requires OAuth authorization before binding")
		}
		affected, err = q.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: pg(resourceID)})
	case "mcp_server":
		m, err := q.GetMCPServerByIDForUpdate(ctx, pg(resourceID))
		if err != nil {
			return notFoundOr(err)
		}
		if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, typ, resourceID); err != nil {
			return err
		}
		if !matchesMCP(need.Spec, m) {
			return service.Detail(service.ErrInvalidInput, "MCP server shape does not match the need")
		}
		if (m.AuthMode == "oauth" || m.AuthMode == "oauth_discovery") && (!m.ScopesVerified || !oauth.CoversScopes(need.ExpectedScopes, m.GrantedScopes)) {
			return service.Detail(service.ErrConflict, "MCP server requires OAuth scope authorization before binding")
		}
		if (m.AuthMode == "oauth" || m.AuthMode == "oauth_discovery") && m.AccessTokenRef == "" {
			return service.Detail(service.ErrConflict, "MCP server requires OAuth authorization before binding")
		}
		affected, err = q.BindMCPServerNeed(ctx, dbq.BindMCPServerNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: pg(resourceID)})
	case "exec_endpoint":
		_, err := q.GetExecEndpointByIDForUpdate(ctx, pg(resourceID))
		if err != nil {
			return notFoundOr(err)
		}
		if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, typ, resourceID); err != nil {
			return err
		}
		affected, err = q.BindExecEndpointNeed(ctx, dbq.BindExecEndpointNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: pg(resourceID)})
	default:
		return service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if typ == "mcp_server" {
		s.refreshAfterMCPChange(ctx, agentID)
	}
	return nil
}

func (s *Service) refreshAfterMCPChange(ctx context.Context, agentID uuid.UUID) {
	if err := s.refresh(ctx, agentID); err != nil {
		s.logger.Warn("refresh agent after MCP binding change failed", zap.String("agent", agentID.String()), zap.Error(err))
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// Unbind clears one need's binding without mutating or authorizing against the
// resource. The operation changes only the agent and requires agent admin.
func (s *Service) Unbind(ctx context.Context, p authz.Principal, agentID uuid.UUID, typ, slug string) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(agentID)); err != nil {
		return notFoundOr(err)
	}
	if err := authz.Authorize(ctx, q, p, manageAction(typ), agentID); err != nil {
		return err
	}
	if _, err := q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams{AgentID: pg(agentID), Type: typ, Slug: slug}); err != nil {
		return notFoundOr(err)
	}
	affected, err := q.UnbindResourceNeed(ctx, dbq.UnbindResourceNeedParams{AgentID: pg(agentID), Type: typ, Slug: slug})
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.Detail(service.ErrNotFound, "resource %q not declared by the agent", slug)
	}
	return tx.Commit(ctx)
}

func notFoundOr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return service.Detail(service.ErrNotFound, "resource not found")
	}
	return err
}
