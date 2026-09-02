// Package resources owns the per-user inventory and management surface for
// reusable resources.
package resources

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	connectorssvc "github.com/airlockrun/airlock/service/connectors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Resource is one resource available to the caller through ownership or a
// grant. It carries no secret material.
type Resource struct {
	ID           uuid.UUID
	Type         string // connection | mcp_server | git_credential | connector | host | connector_target_group
	OwnerID      uuid.UUID
	OwnerName    string
	Slug         string
	Name         string
	DisplayName  string
	AuthMode     string
	Authorized   bool
	AgentCount   int32
	Capabilities []string
	CreatedAt    pgtype.Timestamptz
	HostID       uuid.UUID
	Connector    *ConnectorStatus
}

type ConnectorStatus struct {
	Readiness              string
	ReadinessDetail        string
	Online                 bool
	Lifecycle              string
	ProtocolMajor          int32
	ProtocolMinor          int32
	ArtifactVersion        string
	ArtifactDigest         string
	InterfaceHash          string
	ArtifactFreshness      string
	UpdateStatus           string
	LatestArtifactVersion  string
	LastHeartbeatAt        pgtype.Timestamptz
	ActiveProvenance       string
	ActiveObservationState string
	ObservedActiveDigest   string
	InventoryRevision      uint64
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

// Grant is a user capability grant. Secret material and principal internals are
// deliberately absent from this operator-facing shape.
type Grant struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	Email        string
	DisplayName  string
	Capabilities []string
	CreatedAt    pgtype.Timestamptz
}

type Service struct {
	db         *db.DB
	connectors *connectorssvc.Service
	logger     *zap.Logger
}

func New(d *db.DB, connectors *connectorssvc.Service, logger *zap.Logger) *Service {
	if d == nil {
		panic("resources: db is required")
	}
	if logger == nil {
		panic("resources: logger is required")
	}
	if connectors == nil {
		panic("resources: connector service is required")
	}
	return &Service{db: d, connectors: connectors, logger: logger}
}

// List returns resources available through ownership or a resource grant and
// exposes the caller's capabilities on each one.
func (s *Service) List(ctx context.Context, p authz.Principal) ([]Resource, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.ResourceInventoryView, uuid.Nil); err != nil {
		return nil, err
	}
	principals := principalSet(p)
	governanceView := p.TenantRole == auth.RoleAdmin
	conns, err := q.ListAvailableConnections(ctx, dbq.ListAvailableConnectionsParams{PrincipalIds: principals, GovernanceView: governanceView})
	if err != nil {
		s.logger.Error("list available connections failed", zap.Error(err))
		return nil, err
	}
	mcps, err := q.ListAvailableMCPServers(ctx, dbq.ListAvailableMCPServersParams{PrincipalIds: principals, GovernanceView: governanceView})
	if err != nil {
		s.logger.Error("list available MCP servers failed", zap.Error(err))
		return nil, err
	}
	gitCredentials, err := q.ListAvailableGitCredentials(ctx, dbq.ListAvailableGitCredentialsParams{PrincipalIds: principals, GovernanceView: governanceView})
	if err != nil {
		return nil, err
	}
	hosts, err := q.ListHosts(ctx, dbq.ListHostsParams{PrincipalIds: principals, GovernanceView: governanceView})
	if err != nil {
		return nil, err
	}
	targetGroups, err := q.ListAvailableConnectorTargetGroups(ctx, dbq.ListAvailableConnectorTargetGroupsParams{PrincipalIds: principals, GovernanceView: governanceView})
	if err != nil {
		return nil, err
	}
	connectors, err := q.ListAvailableConnectors(ctx, dbq.ListAvailableConnectorsParams{PrincipalIds: principals, GovernanceView: governanceView})
	if err != nil {
		s.logger.Error("list available connectors failed", zap.Error(err))
		return nil, err
	}
	out := make([]Resource, 0, len(conns)+len(mcps)+len(gitCredentials)+len(connectors)+len(hosts)+len(targetGroups))
	for _, c := range conns {
		out = append(out, Resource{
			ID: uuid.UUID(c.ID.Bytes), OwnerID: uuid.UUID(c.OwnerPrincipalID.Bytes), Type: "connection", Slug: c.Slug, Name: c.Name, DisplayName: c.DisplayName,
			AuthMode: c.AuthMode, Authorized: c.Authorized, AgentCount: c.AgentCount, Capabilities: c.Capabilities, CreatedAt: c.CreatedAt,
		})
	}
	for _, m := range mcps {
		out = append(out, Resource{
			ID: uuid.UUID(m.ID.Bytes), OwnerID: uuid.UUID(m.OwnerPrincipalID.Bytes), Type: "mcp_server", Slug: m.Slug, Name: m.Name, DisplayName: m.DisplayName,
			AuthMode: m.AuthMode, Authorized: m.Authorized, AgentCount: m.AgentCount, Capabilities: m.Capabilities, CreatedAt: m.CreatedAt,
		})
	}
	for _, credential := range gitCredentials {
		out = append(out, Resource{
			ID: uuid.UUID(credential.ID.Bytes), OwnerID: uuid.UUID(credential.OwnerPrincipalID.Bytes), Type: "git_credential",
			Name: credential.Name, DisplayName: credential.Name, AuthMode: credential.Type, Authorized: true,
			Capabilities: credential.Capabilities, CreatedAt: credential.CreatedAt,
		})
	}
	for _, host := range hosts {
		out = append(out, Resource{
			ID: uuid.UUID(host.ID.Bytes), OwnerID: uuid.UUID(host.OwnerPrincipalID.Bytes), Type: "host",
			Name: host.Name, DisplayName: host.Name, AuthMode: host.AccessMode, Authorized: host.Lifecycle == "active",
			AgentCount: host.ConnectorCount, Capabilities: host.Capabilities, CreatedAt: host.CreatedAt,
		})
	}
	for _, group := range targetGroups {
		out = append(out, Resource{
			ID: uuid.UUID(group.ID.Bytes), OwnerID: uuid.UUID(group.OwnerPrincipalID.Bytes), Type: "connector_target_group",
			Name: group.Name, DisplayName: group.Name, AuthMode: "target_group", Authorized: true,
			AgentCount: group.MemberCount, Capabilities: group.Capabilities, CreatedAt: group.CreatedAt,
		})
	}
	for _, connector := range connectors {
		name := connector.Name.String
		if name == "" {
			name = connector.Slug
		}
		connectorID := uuid.UUID(connector.ID.Bytes)
		row, artifactStatus, err := s.connectors.ResourceStatus(ctx, connectorID)
		if err != nil {
			return nil, err
		}
		out = append(out, Resource{
			ID: uuid.UUID(connector.ID.Bytes), OwnerID: uuid.UUID(connector.OwnerPrincipalID.Bytes), Type: "connector", Slug: connector.Slug, Name: name, DisplayName: connector.DisplayName,
			AuthMode: "installation_token", Authorized: connector.Authorized, AgentCount: connector.AgentCount,
			Capabilities: connector.Capabilities, CreatedAt: connector.CreatedAt, HostID: uuid.UUID(row.HostID.Bytes),
			Connector: &ConnectorStatus{
				Readiness: row.Readiness, ReadinessDetail: row.ReadinessMessage.String,
				Online: row.Lifecycle == "active" && row.Readiness != "offline", Lifecycle: row.Lifecycle,
				ProtocolMajor: row.ProtocolMajor.Int32, ProtocolMinor: row.ProtocolMinor.Int32,
				ArtifactVersion: row.ArtifactVersion.String, ArtifactDigest: row.ArtifactDigest.String,
				InterfaceHash: row.InterfaceHash.String, ArtifactFreshness: artifactStatus.Freshness,
				UpdateStatus: artifactStatus.UpdateStatus, LatestArtifactVersion: artifactStatus.LatestVersion,
				LastHeartbeatAt:  row.LastSeenAt,
				ActiveProvenance: row.ActiveProvenance, ActiveObservationState: row.ActiveObservationState,
				ObservedActiveDigest: row.ObservedActiveDigest.String, InventoryRevision: uint64(row.InventoryRevision),
			},
		})
	}
	ownerIDs := make([]pgtype.UUID, 0, len(out))
	for _, resource := range out {
		ownerIDs = append(ownerIDs, pgtype.UUID{Bytes: resource.OwnerID, Valid: true})
	}
	owners, err := q.ResolvePrincipalNames(ctx, ownerIDs)
	if err != nil {
		return nil, err
	}
	ownerNames := make(map[uuid.UUID]string, len(owners))
	for _, owner := range owners {
		ownerNames[uuid.UUID(owner.ID.Bytes)] = owner.Name
	}
	for i := range out {
		out[i].OwnerName = ownerNames[out[i].OwnerID]
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

// ListGrants returns user grants only to resource managers.
func (s *Service) ListGrants(ctx context.Context, p authz.Principal, typ string, id uuid.UUID) ([]Grant, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, id); err != nil {
		return nil, err
	}
	rows, err := q.ListResourceGrantDetails(ctx, dbq.ListResourceGrantDetailsParams{ResourceType: typ, ResourceID: pgtype.UUID{Bytes: id, Valid: true}})
	if err != nil {
		return nil, err
	}
	out := make([]Grant, len(rows))
	for i, row := range rows {
		out[i] = Grant{
			ID: uuid.UUID(row.ID.Bytes), UserID: uuid.UUID(row.GranteeID.Bytes), Email: row.Email,
			DisplayName: row.GranteeName, Capabilities: row.Capabilities, CreatedAt: row.CreatedAt,
		}
	}
	return out, nil
}

// UpsertGrant creates or replaces one user's independent capabilities.
func (s *Service) UpsertGrant(ctx context.Context, p authz.Principal, typ string, id, userID uuid.UUID, capabilities []string) error {
	capabilities, err := canonicalCapabilities(typ, capabilities)
	if err != nil {
		return err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, id); err != nil {
		return err
	}
	if err := authz.LockResource(ctx, q, typ, id); err != nil {
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, id); err != nil {
		return err
	}
	owner, err := authz.ResourceOwner(ctx, q, typ, id)
	if err != nil {
		return err
	}
	if owner == userID {
		return service.Detail(service.ErrInvalidInput, "resource owner already has every supported capability")
	}
	if _, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: userID, Valid: true}); errors.Is(err, pgx.ErrNoRows) {
		return service.Detail(service.ErrInvalidInput, "grant target must be an existing user")
	} else if err != nil {
		return err
	}
	params := dbq.UpsertConnectionResourceGrantParams{ResourceID: pgtype.UUID{Bytes: id, Valid: true}, GranteeID: pgtype.UUID{Bytes: userID, Valid: true}, Capabilities: capabilities}
	switch typ {
	case "connection":
		_, err = q.UpsertConnectionResourceGrant(ctx, params)
	case "mcp_server":
		_, err = q.UpsertMCPServerResourceGrant(ctx, dbq.UpsertMCPServerResourceGrantParams(params))
	case "git_credential":
		_, err = q.UpsertGitCredentialResourceGrant(ctx, dbq.UpsertGitCredentialResourceGrantParams(params))
	case "connector":
		_, err = q.UpsertConnectorResourceGrant(ctx, dbq.UpsertConnectorResourceGrantParams(params))
	case "host":
		_, err = q.UpsertHostResourceGrant(ctx, dbq.UpsertHostResourceGrantParams(params))
	case "connector_target_group":
		_, err = q.UpsertConnectorTargetGroupResourceGrant(ctx, dbq.UpsertConnectorTargetGroupResourceGrantParams(params))
	default:
		return service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteGrant removes one user's grant without changing resource bindings.
func (s *Service) DeleteGrant(ctx context.Context, p authz.Principal, typ string, id, userID uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, id); err != nil {
		return err
	}
	if err := authz.LockResource(ctx, q, typ, id); err != nil {
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, typ, id); err != nil {
		return err
	}
	affected, err := q.DeleteResourceGrant(ctx, dbq.DeleteResourceGrantParams{
		ResourceType: typ, ResourceID: pgtype.UUID{Bytes: id, Valid: true}, GranteeID: pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	return tx.Commit(ctx)
}

// Transfer moves ownership to an existing user and records the actor and both
// owners in the same transaction. Existing grants and agent bindings remain.
func (s *Service) Transfer(ctx context.Context, p authz.Principal, typ string, id, newOwnerID uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.AuthorizeResourceTransfer(ctx, q, p, typ, id); err != nil {
		return err
	}
	if err := authz.LockResource(ctx, q, typ, id); err != nil {
		return err
	}
	if err := authz.AuthorizeResourceTransfer(ctx, q, p, typ, id); err != nil {
		return err
	}
	owner, err := authz.ResourceOwner(ctx, q, typ, id)
	if err != nil {
		return err
	}
	if owner == newOwnerID {
		return service.Detail(service.ErrInvalidInput, "user already owns the resource")
	}
	if _, err := q.GetUserByIDForUpdate(ctx, pgtype.UUID{Bytes: newOwnerID, Valid: true}); errors.Is(err, pgx.ErrNoRows) {
		return service.Detail(service.ErrInvalidInput, "transfer target must be an existing user")
	} else if err != nil {
		return err
	}
	params := dbq.TransferConnectionResourceOwnershipParams{NewOwnerUserID: pgtype.UUID{Bytes: newOwnerID, Valid: true}, ResourceID: pgtype.UUID{Bytes: id, Valid: true}}
	var affected int64
	switch typ {
	case "connection":
		affected, err = q.TransferConnectionResourceOwnership(ctx, params)
	case "mcp_server":
		affected, err = q.TransferMCPServerResourceOwnership(ctx, dbq.TransferMCPServerResourceOwnershipParams(params))
	case "git_credential":
		affected, err = q.TransferGitCredentialResourceOwnership(ctx, dbq.TransferGitCredentialResourceOwnershipParams(params))
	case "connector":
		affected, err = q.TransferConnectorResourceOwnership(ctx, dbq.TransferConnectorResourceOwnershipParams(params))
	case "host":
		affected, err = q.TransferHostResourceOwnership(ctx, dbq.TransferHostResourceOwnershipParams(params))
	case "connector_target_group":
		affected, err = q.TransferConnectorTargetGroupResourceOwnership(ctx, dbq.TransferConnectorTargetGroupResourceOwnershipParams(params))
	default:
		return service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	if err := q.InsertResourceOwnershipTransfer(ctx, dbq.InsertResourceOwnershipTransferParams{
		ResourceType: typ, ResourceID: pgtype.UUID{Bytes: id, Valid: true}, ActorUserID: pgtype.UUID{Bytes: p.UserID, Valid: true},
		PreviousOwnerPrincipalID: pgtype.UUID{Bytes: owner, Valid: true}, NewOwnerUserID: pgtype.UUID{Bytes: newOwnerID, Valid: true},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func canonicalCapabilities(typ string, values []string) ([]string, error) {
	supported := authz.SupportedResourceCapabilities(typ)
	if len(supported) == 0 {
		return nil, service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	if len(values) == 0 {
		return nil, service.Detail(service.ErrInvalidInput, "at least one capability is required")
	}
	wanted := make(map[string]bool, len(values))
	for _, value := range values {
		if !slices.Contains(supported, value) {
			return nil, service.Detail(service.ErrInvalidInput, "invalid %s capability %q", typ, value)
		}
		wanted[value] = true
	}
	out := make([]string, 0, len(wanted))
	for _, value := range supported {
		if wanted[value] {
			out = append(out, value)
		}
	}
	return out, nil
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
	case "connector":
		rows, err := q.ListConnectorConsumers(ctx, pgID)
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
	if err := authz.LockResource(ctx, q, typ, id); err != nil {
		return err
	}
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
	case "connector":
		affected, err = q.RenameConnector(ctx, dbq.RenameConnectorParams{ID: pgID, DisplayName: displayName})
	default:
		return service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
	if err != nil {
		return err
	}
	if (typ == "connector" && affected == 0) || (typ != "connector" && affected != 1) {
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
	if err := authz.LockResource(ctx, q, typ, id); err != nil {
		return err
	}
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
	case "connector":
		return service.Detail(service.ErrInvalidInput, "connector access is managed by its host")
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

// Delete removes a resource. Connector rows are tombstoned for durable cleanup.
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
	case "connector":
		return service.Detail(service.ErrInvalidInput, "connector removal is managed by its host")
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
	}
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	return tx.Commit(ctx)
}
