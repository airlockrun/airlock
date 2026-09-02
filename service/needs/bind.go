package needs

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/service"
	connectorssvc "github.com/airlockrun/airlock/service/connectors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	Type                    string
	Slug                    string
	Description             string
	Bound                   bool
	BoundResourceID         uuid.UUID
	ConnectorContractID     string
	ConnectorCommands       []connectorssvc.Command
	ConnectorDirectories    []connectorssvc.Directory
	ConnectorMultiple       bool
	BoundConnectorID        uuid.UUID
	BoundConnectorGroupID   uuid.UUID
	BoundConnectorGroupName string
}

type ConnectorTargetGroupCandidate struct {
	Group                      dbq.ConnectorTargetGroup
	MemberCount                int32
	ReadyMemberCount           int32
	CompatibleReadyMemberCount int32
	Eligible                   bool
	Reason                     string
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
		if n.Type == "connector" {
			spec, err := connectorssvc.ParseNeedSpec(n.Spec)
			if err != nil {
				return nil, service.Detail(service.ErrConflict, "connector need %q has an invalid persisted contract: %v", n.Slug, err)
			}
			info.ConnectorContractID = spec.ContractID
			info.ConnectorCommands = spec.Commands
			info.ConnectorDirectories = spec.Directories
			info.ConnectorMultiple = spec.Multiple
		}
		switch {
		case n.BoundConnectionID.Valid:
			info.Bound, info.BoundResourceID = true, uuid.UUID(n.BoundConnectionID.Bytes)
		case n.BoundMcpID.Valid:
			info.Bound, info.BoundResourceID = true, uuid.UUID(n.BoundMcpID.Bytes)
		case n.BoundConnectorID.Valid:
			info.Bound, info.BoundResourceID = true, uuid.UUID(n.BoundConnectorID.Bytes)
			info.BoundConnectorID = info.BoundResourceID
		case n.BoundConnectorGroupID.Valid:
			info.Bound, info.BoundResourceID = true, uuid.UUID(n.BoundConnectorGroupID.Bytes)
			info.BoundConnectorGroupID = info.BoundResourceID
			info.BoundConnectorGroupName = n.BoundConnectorGroupName.String
		}
		out[i] = info
	}
	return out, nil
}

// manageAction is the agent-axis gate for managing a resource type.
func manageAction(typ string) (authz.Action, error) {
	switch typ {
	case "connection", "mcp_server":
		return authz.AgentConnections, nil
	case "connector":
		return authz.AgentConnectors, nil
	default:
		return "", service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
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
	action, err := manageAction(typ)
	if err != nil {
		return uuid.Nil, err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(agentID)); err != nil {
		return uuid.Nil, notFoundOr(err)
	}
	if err := authz.Authorize(ctx, q, p, action, agentID); err != nil {
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
	action, err := manageAction(typ)
	if err != nil {
		return nil, err
	}
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, action, agentID); err != nil {
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
	case "connector":
		rows, err := q.ListConnectorsAvailableToPrincipal(ctx, principals)
		if err != nil {
			return nil, err
		}
		needSpec, err := connectorssvc.ParseNeedSpec(need.Spec)
		if err != nil {
			return nil, service.Detail(service.ErrInvalidInput, "%v", err)
		}
		for _, connector := range rows {
			if connector.InterfaceDescriptor == nil {
				continue
			}
			descriptor, err := connectorssvc.ParseDescriptor(connector.InterfaceDescriptor)
			if err != nil || connectorssvc.Compatible(needSpec, descriptor) != nil {
				continue
			}
			id := uuid.UUID(connector.ID.Bytes)
			capabilities, err := authz.ResourceCapabilities(ctx, q, p, typ, id)
			if err != nil {
				return nil, err
			}
			consumers, err := q.ListConnectorConsumers(ctx, connector.ID)
			if err != nil {
				return nil, err
			}
			name := connector.Name.String
			if name == "" {
				name = connector.Kind.String
			}
			readiness := connector.Readiness
			out = append(out, Candidate{
				ResourceID: id, Name: name, DisplayName: connector.DisplayName, Slug: connector.Slug,
				Readiness: readiness, Authorized: connector.Lifecycle == "active", Configured: connector.InterfaceDescriptor != nil,
				AgentCount: int32(len(consumers)), Capabilities: capabilities,
			})
		}
	default:
		return nil, service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	return out, nil
}

func (s *Service) ListConnectorTargetGroupCandidates(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) ([]ConnectorTargetGroupCandidate, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentConnectors, agentID); err != nil {
		return nil, err
	}
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: "connector", Slug: slug})
	if err != nil {
		return nil, notFoundOr(err)
	}
	spec, err := connectorssvc.ParseNeedSpec(need.Spec)
	if err != nil {
		return nil, service.Detail(service.ErrConflict, "%v", err)
	}
	if !spec.Multiple {
		return nil, service.Detail(service.ErrInvalidInput, "connector need is not multi-target")
	}
	rows, err := q.ListConnectorTargetGroups(ctx, dbq.ListConnectorTargetGroupsParams{PrincipalIds: s.granteeOwners(p), GovernanceView: p.TenantRole == auth.RoleAdmin})
	if err != nil {
		return nil, err
	}
	out := make([]ConnectorTargetGroupCandidate, len(rows))
	for i, row := range rows {
		candidate := ConnectorTargetGroupCandidate{
			Group: dbq.ConnectorTargetGroup{
				ID: row.ID, OwnerPrincipalID: row.OwnerPrincipalID, Name: row.Name,
				Description: row.Description, ContractID: row.ContractID,
				CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
			},
			MemberCount: row.MemberCount, ReadyMemberCount: row.ReadyMemberCount,
		}
		if _, capErr := authz.ResourceCapabilities(ctx, q, p, "connector_target_group", uuid.UUID(row.ID.Bytes)); capErr != nil {
			if errors.Is(capErr, service.ErrForbidden) {
				candidate.Reason = "Bind access to this target group is required."
				out[i] = candidate
				continue
			}
			return nil, capErr
		}
		if row.ContractID != spec.ContractID {
			candidate.Reason = "Target group contract ID does not match this connector need."
		} else {
			candidate.CompatibleReadyMemberCount, candidate.Eligible, candidate.Reason, err = connectorTargetGroupEligibility(ctx, q, p, row.ID, spec)
			if err != nil {
				return nil, err
			}
		}
		out[i] = candidate
	}
	return out, nil
}

func connectorTargetGroupEligibility(ctx context.Context, q *dbq.Queries, p authz.Principal, groupID pgtype.UUID, spec connectorssvc.NeedSpec) (int32, bool, string, error) {
	members, err := q.ListConnectorTargetGroupMembers(ctx, groupID)
	if err != nil {
		return 0, false, "", err
	}
	if len(members) == 0 {
		return 0, false, "Target group has no members.", nil
	}
	ready := int32(0)
	for _, member := range members {
		memberID := uuid.UUID(member.ID.Bytes)
		if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, "connector", memberID); err != nil {
			if errors.Is(err, service.ErrForbidden) || errors.Is(err, service.ErrNotFound) {
				return ready, false, "Bind access to every target group member is required.", nil
			}
			return 0, false, "", err
		}
		descriptor, err := connectorssvc.ParseDescriptor(member.InterfaceDescriptor)
		if member.Lifecycle != "active" || err != nil || connectorssvc.Compatible(spec, descriptor) != nil {
			return ready, false, "Every target group member must satisfy the complete connector need.", nil
		}
		if member.Readiness == "ready" {
			ready++
		}
	}
	if ready == 0 {
		return 0, false, "Target group requires at least one ready member.", nil
	}
	return ready, true, "", nil
}

// BindExisting binds an existing resource after checking agent admin, resource
// bind capability, and shape compatibility in one transaction.
func (s *Service) BindExisting(ctx context.Context, p authz.Principal, agentID uuid.UUID, typ, slug string, resourceID uuid.UUID) error {
	action, err := manageAction(typ)
	if err != nil {
		return err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(agentID)); err != nil {
		return notFoundOr(err)
	}
	if err := authz.Authorize(ctx, q, p, action, agentID); err != nil {
		return err
	}
	needParams := dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: typ, Slug: slug}
	var need dbq.AgentResourceNeed
	if typ == "connector" {
		need, err = q.GetResourceNeed(ctx, needParams)
	} else {
		need, err = q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams(needParams))
	}
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
	case "connector":
		locked, err := connectorssvc.LockResources(ctx, q, []uuid.UUID{resourceID})
		if err != nil {
			return notFoundOr(err)
		}
		need, err = q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams(needParams))
		if err != nil {
			return notFoundOr(err)
		}
		if need.BoundConnectorID.Valid || need.BoundConnectorGroupID.Valid {
			return service.Detail(service.ErrConflict, "connector need must be explicitly unbound before rebinding")
		}
		connector := locked[resourceID]
		if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, typ, resourceID); err != nil {
			return err
		}
		if connector.Lifecycle != "active" || connector.Readiness != "ready" {
			return service.Detail(service.ErrConflict, "connector must be active and ready before binding")
		}
		needSpec, err := connectorssvc.ParseNeedSpec(need.Spec)
		if err != nil {
			return service.Detail(service.ErrInvalidInput, "%v", err)
		}
		descriptor, err := connectorssvc.ParseDescriptor(connector.InterfaceDescriptor)
		if err != nil {
			return service.Detail(service.ErrConflict, "connector has not published a valid interface")
		}
		if err := connectorssvc.Compatible(needSpec, descriptor); err != nil {
			return service.Detail(service.ErrInvalidInput, "%v", err)
		}
		if err := q.ReserveConnectorForNeed(ctx, dbq.ReserveConnectorForNeedParams{ConnectorID: pg(resourceID), NeedID: need.ID}); err != nil {
			if reservationConflict(err) {
				return service.Detail(service.ErrConflict, "connector is already reserved by another need")
			}
			return err
		}
		affected, err = q.BindConnectorNeed(ctx, dbq.BindConnectorNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: pg(resourceID)})
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

func (s *Service) BindConnectorGroup(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string, groupID uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(agentID)); err != nil {
		return notFoundOr(err)
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentConnectors, agentID); err != nil {
		return err
	}
	discovered, err := q.ListConnectorTargetGroupMembers(ctx, pg(groupID))
	if err != nil {
		return notFoundOr(err)
	}
	memberIDs := make([]uuid.UUID, len(discovered))
	for i, member := range discovered {
		memberIDs[i] = uuid.UUID(member.ID.Bytes)
	}
	locked, err := connectorssvc.LockResources(ctx, q, memberIDs)
	if err != nil {
		return notFoundOr(err)
	}
	group, err := q.GetConnectorTargetGroupForUpdate(ctx, pg(groupID))
	if err != nil {
		return notFoundOr(err)
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, "connector_target_group", groupID); err != nil {
		return err
	}
	need, err := q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams{AgentID: pg(agentID), Type: "connector", Slug: slug})
	if err != nil {
		return notFoundOr(err)
	}
	spec, err := connectorssvc.ParseNeedSpec(need.Spec)
	if err != nil {
		return service.Detail(service.ErrConflict, "%v", err)
	}
	if !spec.Multiple {
		return service.Detail(service.ErrInvalidInput, "connector need is not multi-target")
	}
	if need.BoundConnectorID.Valid || need.BoundConnectorGroupID.Valid {
		return service.Detail(service.ErrConflict, "connector need must be explicitly unbound before rebinding")
	}
	if group.ContractID != spec.ContractID {
		return service.Detail(service.ErrInvalidInput, "connector target group contract ID does not match the need")
	}
	members, err := q.ListConnectorTargetGroupMembers(ctx, pg(groupID))
	if err != nil {
		return err
	}
	if len(members) == 0 {
		return service.Detail(service.ErrConflict, "connector target group has no members")
	}
	ready := 0
	for _, member := range members {
		memberID := uuid.UUID(member.ID.Bytes)
		connector, ok := locked[memberID]
		if !ok {
			return service.Detail(service.ErrConflict, "connector target group membership changed; retry binding")
		}
		if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, "connector", memberID); err != nil {
			return err
		}
		descriptor, parseErr := connectorssvc.ParseDescriptor(connector.InterfaceDescriptor)
		if connector.Lifecycle != "active" || parseErr != nil || connectorssvc.Compatible(spec, descriptor) != nil {
			return service.Detail(service.ErrConflict, "every target group member must satisfy the complete connector need")
		}
		if connector.Readiness == "ready" {
			ready++
		}
	}
	if ready == 0 {
		return service.Detail(service.ErrConflict, "connector target group requires at least one ready member")
	}
	reserved, err := q.ReserveConnectorTargetGroupForNeed(ctx, dbq.ReserveConnectorTargetGroupForNeedParams{NeedID: need.ID, GroupID: pg(groupID)})
	if err != nil {
		if reservationConflict(err) {
			return service.Detail(service.ErrConflict, "a target group member is already reserved by another need")
		}
		return err
	}
	if len(reserved) != len(members) {
		return errors.New("target group reservation did not cover every member")
	}
	affected, err := q.BindConnectorGroupNeed(ctx, dbq.BindConnectorGroupNeedParams{AgentID: pg(agentID), Slug: slug, GroupID: pg(groupID)})
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	return tx.Commit(ctx)
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
	action, err := manageAction(typ)
	if err != nil {
		return err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(agentID)); err != nil {
		return notFoundOr(err)
	}
	if err := authz.Authorize(ctx, q, p, action, agentID); err != nil {
		return err
	}
	needParams := dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: typ, Slug: slug}
	need, err := q.GetResourceNeed(ctx, needParams)
	if err != nil {
		return notFoundOr(err)
	}
	if typ == "connector" {
		connectorIDs := make([]uuid.UUID, 0, 1)
		if need.BoundConnectorID.Valid {
			connectorIDs = append(connectorIDs, uuid.UUID(need.BoundConnectorID.Bytes))
		}
		if need.BoundConnectorGroupID.Valid {
			members, err := q.ListConnectorTargetGroupMembers(ctx, need.BoundConnectorGroupID)
			if err != nil {
				return err
			}
			for _, member := range members {
				connectorIDs = append(connectorIDs, uuid.UUID(member.ID.Bytes))
			}
		}
		if _, err := connectorssvc.LockResources(ctx, q, connectorIDs); err != nil {
			return notFoundOr(err)
		}
		if need.BoundConnectorGroupID.Valid {
			if _, err := q.GetConnectorTargetGroupForUpdate(ctx, need.BoundConnectorGroupID); err != nil {
				return notFoundOr(err)
			}
		}
		need, err = q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams(needParams))
		if err != nil {
			return notFoundOr(err)
		}
		count, err := q.CountNonterminalConnectorJobsForNeed(ctx, need.ID)
		if err != nil {
			return err
		}
		if count != 0 {
			return service.Detail(service.ErrConflict, "connector need has nonterminal work; cancel or complete it before unbinding")
		}
		if _, err := q.DeleteConnectorReservationsForNeed(ctx, need.ID); err != nil {
			return err
		}
	} else {
		need, err = q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams(needParams))
		if err != nil {
			return notFoundOr(err)
		}
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

func reservationConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func notFoundOr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return service.Detail(service.ErrNotFound, "resource not found")
	}
	return err
}
