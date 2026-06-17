package needs

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Service exposes the operator-facing need lifecycle: create a resource for a
// need, bind an existing one, and list compatible candidates.
type Service struct {
	db     *db.DB
	logger *zap.Logger
}

func NewService(database *db.DB, logger *zap.Logger) *Service {
	if database == nil || logger == nil {
		panic("needs: nil dependency")
	}
	return &Service{db: database, logger: logger}
}

// Candidate is a resource that could satisfy a need: shape-compatible and owned
// by a principal in the caller's grantee set.
type Candidate struct {
	ResourceID uuid.UUID
	Name       string
	Slug       string
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

// scopesSubset reports whether every comma-separated scope in need is present
// in have (a resource with fewer scopes can't satisfy the need without reauth).
func scopesSubset(need, have string) bool {
	set := map[string]bool{}
	for _, s := range strings.Split(have, ",") {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	for _, s := range strings.Split(need, ",") {
		if s = strings.TrimSpace(s); s != "" && !set[s] {
			return false
		}
	}
	return true
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
		jsonEqual(s.Headers, c.Headers) &&
		scopesSubset(s.Scopes, c.Scopes)
}

func matchesMCP(needSpec []byte, m dbq.AgentMcpServer) bool {
	var s mcpSpec
	_ = json.Unmarshal(needSpec, &s)
	return s.URL == m.Url &&
		s.AuthMode == m.AuthMode &&
		jsonEqual(s.AuthInjection, m.AuthInjection) &&
		scopesSubset(s.Scopes, m.Scopes)
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
func (s *Service) CreateResourceForNeed(ctx context.Context, p authz.Principal, agentID uuid.UUID, typ, slug string) (uuid.UUID, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, manageAction(typ), agentID); err != nil {
		return uuid.Nil, err
	}
	return CreateForNeed(ctx, q, p, agentID, typ, slug)
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
	owners := s.granteeOwners(p)
	var out []Candidate
	switch typ {
	case "connection":
		rows, err := q.ListConnectionsByOwners(ctx, owners)
		if err != nil {
			return nil, err
		}
		for _, c := range rows {
			if matchesConnection(need.Spec, c) {
				out = append(out, Candidate{ResourceID: uuid.UUID(c.ID.Bytes), Name: c.Name, Slug: c.Slug})
			}
		}
	case "mcp_server":
		rows, err := q.ListMCPServersByOwners(ctx, owners)
		if err != nil {
			return nil, err
		}
		for _, m := range rows {
			if matchesMCP(need.Spec, m) {
				out = append(out, Candidate{ResourceID: uuid.UUID(m.ID.Bytes), Name: m.Name, Slug: m.Slug})
			}
		}
	case "exec_endpoint":
		rows, err := q.ListExecEndpointsByOwners(ctx, owners)
		if err != nil {
			return nil, err
		}
		for _, e := range rows {
			out = append(out, Candidate{ResourceID: uuid.UUID(e.ID.Bytes), Name: e.Slug, Slug: e.Slug})
		}
	default:
		return nil, service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	return out, nil
}

// BindExisting binds an existing resource to the need after verifying the caller
// may bind it (owns it via its grantee set) and that its shape matches the need.
func (s *Service) BindExisting(ctx context.Context, p authz.Principal, agentID uuid.UUID, typ, slug string, resourceID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, manageAction(typ), agentID); err != nil {
		return err
	}
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: typ, Slug: slug})
	if err != nil {
		return service.Detail(service.ErrNotFound, "resource %q not declared by the agent", slug)
	}
	owned := func(owner pgtype.UUID) bool {
		for _, id := range p.GranteeSet() {
			if owner.Valid && uuid.UUID(owner.Bytes) == id {
				return true
			}
		}
		return false
	}
	switch typ {
	case "connection":
		c, err := q.GetConnectionByID(ctx, pg(resourceID))
		if err != nil {
			return notFoundOr(err)
		}
		if !owned(c.OwnerPrincipalID) {
			return service.Detail(service.ErrForbidden, "you do not own that connection")
		}
		if !matchesConnection(need.Spec, c) {
			return service.Detail(service.ErrInvalidInput, "connection shape does not match the need")
		}
		return q.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: pg(resourceID)})
	case "mcp_server":
		m, err := q.GetMCPServerByID(ctx, pg(resourceID))
		if err != nil {
			return notFoundOr(err)
		}
		if !owned(m.OwnerPrincipalID) {
			return service.Detail(service.ErrForbidden, "you do not own that MCP server")
		}
		if !matchesMCP(need.Spec, m) {
			return service.Detail(service.ErrInvalidInput, "MCP server shape does not match the need")
		}
		return q.BindMCPServerNeed(ctx, dbq.BindMCPServerNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: pg(resourceID)})
	case "exec_endpoint":
		e, err := q.GetExecEndpointByID(ctx, pg(resourceID))
		if err != nil {
			return notFoundOr(err)
		}
		if !owned(e.OwnerPrincipalID) {
			return service.Detail(service.ErrForbidden, "you do not own that exec endpoint")
		}
		return q.BindExecEndpointNeed(ctx, dbq.BindExecEndpointNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: pg(resourceID)})
	default:
		return service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
}

func notFoundOr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return service.Detail(service.ErrNotFound, "resource not found")
	}
	return err
}
