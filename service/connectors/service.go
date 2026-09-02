package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type Service struct {
	db     *db.DB
	logger *zap.Logger
}

func New(database *db.DB, logger *zap.Logger) *Service {
	if database == nil || logger == nil {
		panic("connectors: nil dependency")
	}
	return &Service{db: database, logger: logger}
}

type Resource struct {
	Row            dbq.ConnectorResource
	Capabilities   []string
	AgentCount     int32
	OwnerName      string
	OwnerKind      string
	Commands       []Command
	Directories    []Directory
	ArtifactStatus ArtifactStatus
	Grants         []ResourceGrant
	Consumers      []Consumer
}

type ArtifactStatus struct {
	Freshness             string
	UpdateStatus          string
	LatestVersion         string
	LatestDigest          string
	LatestInterfaceHash   string
	LatestArtifactCreated pgtype.Timestamptz
}

type ResourceGrant struct {
	ID           uuid.UUID
	GranteeID    uuid.UUID
	GranteeName  string
	GranteeKind  string
	Capabilities []string
}

type Consumer struct {
	AgentID        uuid.UUID
	AgentName      string
	AgentSlug      string
	NeedType       string
	NeedSlug       string
	CanAccessAgent bool
}

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func text(value string) pgtype.Text { return pgtype.Text{String: value, Valid: value != ""} }

func (s *Service) PublishInterface(ctx context.Context, connectorID uuid.UUID, protocolMajor, protocolMinor int32, features []string, serviceMode, artifactDigest, readiness, readinessMessage string, descriptor InterfaceDescriptor) (dbq.ConnectorResource, error) {
	if protocolMajor != ProtocolMajor || protocolMinor < 0 {
		return dbq.ConnectorResource{}, service.Detail(service.ErrConflict, "unsupported connector protocol version %d.%d", protocolMajor, protocolMinor)
	}
	if !validReadiness(readiness) {
		return dbq.ConnectorResource{}, service.Detail(service.ErrInvalidInput, "invalid connector readiness")
	}
	if serviceMode != "user" && serviceMode != "system" {
		return dbq.ConnectorResource{}, service.Detail(service.ErrInvalidInput, "invalid connector service mode")
	}
	if err := ValidateDescriptor(descriptor); err != nil {
		return dbq.ConnectorResource{}, service.Detail(service.ErrInvalidInput, "%v", err)
	}
	if artifactDigest != "" {
		if err := protocol.ValidateArtifactDigest(artifactDigest); err != nil {
			return dbq.ConnectorResource{}, service.Detail(service.ErrInvalidInput, "connector artifact digest %v", err)
		}
	}
	interfaceHash, raw, err := DescriptorHash(descriptor)
	if err != nil {
		return dbq.ConnectorResource{}, err
	}
	artifactLock, err := s.db.AcquireAdvisoryLock(ctx, "connector-artifact-gc")
	if err != nil {
		return dbq.ConnectorResource{}, err
	}
	defer artifactLock.Unlock()
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.ConnectorResource{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	current, err := q.GetConnectorResourceForUpdate(ctx, pg(connectorID))
	if err != nil {
		return dbq.ConnectorResource{}, err
	}
	artifactSetID := pgtype.UUID{}
	if artifactDigest != "" {
		artifactSetID, err = q.FindConnectorArtifactPublication(ctx, dbq.FindConnectorArtifactPublicationParams{
			ArtifactDigest: artifactDigest, Kind: descriptor.Kind, ContractID: descriptor.ContractID,
			ArtifactVersion: descriptor.ArtifactVersion, ProtocolMajor: protocolMajor, ProtocolMinor: protocolMinor,
			Features: features, ServiceMode: pgtype.Text{String: serviceMode, Valid: true}, InterfaceHash: interfaceHash, InterfaceDescriptor: raw,
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return dbq.ConnectorResource{}, err
		}
	}
	if current.InterfaceHash.Valid {
		if !current.Kind.Valid || current.Kind.String != descriptor.Kind || !current.ContractID.Valid || current.ContractID.String != descriptor.ContractID ||
			!current.ServiceMode.Valid || current.ServiceMode.String != serviceMode {
			return dbq.ConnectorResource{}, service.Detail(service.ErrConflict, "connector kind, contract, and service mode cannot change after installation")
		}
		if artifactDigest != "" && (current.ArtifactDigest.String != artifactDigest || current.InterfaceHash.String != interfaceHash) && !artifactSetID.Valid {
			return dbq.ConnectorResource{}, service.Detail(service.ErrForbidden, "connector upgrade does not match a successful artifact publication")
		}
	} else if artifactDigest != "" && !artifactSetID.Valid {
		return dbq.ConnectorResource{}, service.Detail(service.ErrForbidden, "connector publication does not match a successful artifact")
	}
	row, err := q.PublishConnectorInterface(ctx, dbq.PublishConnectorInterfaceParams{
		Kind: text(descriptor.Kind), ContractID: text(descriptor.ContractID), Name: text(descriptor.Name), Description: text(descriptor.Description),
		ProtocolMajor: pgtype.Int4{Int32: protocolMajor, Valid: true}, ProtocolMinor: pgtype.Int4{Int32: protocolMinor, Valid: true},
		Features: features, ServiceMode: pgtype.Text{String: serviceMode, Valid: true}, ArtifactVersion: text(descriptor.ArtifactVersion), ArtifactDigest: text(artifactDigest),
		ArtifactSetID: artifactSetID, InterfaceDescriptor: raw, InterfaceHash: text(interfaceHash), Readiness: readiness, ReadinessMessage: text(readinessMessage), ID: pg(connectorID),
	})
	if err != nil {
		return dbq.ConnectorResource{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.ConnectorResource{}, err
	}
	return row, nil
}

func (s *Service) Heartbeat(ctx context.Context, connectorID uuid.UUID, protocolMajor, protocolMinor int32, features []string, artifactVersion, artifactDigest, interfaceHash, readiness, readinessMessage string) (dbq.ConnectorResource, error) {
	if protocolMajor != ProtocolMajor || protocolMinor < 0 {
		readiness, readinessMessage = "incompatible_protocol", fmt.Sprintf("unsupported connector protocol version %d.%d", protocolMajor, protocolMinor)
	}
	if !validReadiness(readiness) {
		return dbq.ConnectorResource{}, service.Detail(service.ErrInvalidInput, "invalid connector readiness")
	}
	if artifactDigest != "" {
		if err := protocol.ValidateArtifactDigest(artifactDigest); err != nil {
			return dbq.ConnectorResource{}, service.Detail(service.ErrInvalidInput, "connector artifact digest %v", err)
		}
	}
	if artifactDigest != "" {
		artifactLock, err := s.db.AcquireAdvisoryLock(ctx, "connector-artifact-gc")
		if err != nil {
			return dbq.ConnectorResource{}, err
		}
		defer artifactLock.Unlock()
	}
	return dbq.New(s.db.Pool()).HeartbeatConnector(ctx, dbq.HeartbeatConnectorParams{
		ReportedInterfaceHash: text(interfaceHash), ArtifactDigest: text(artifactDigest), Readiness: readiness, ReadinessMessage: text(readinessMessage), ID: pg(connectorID),
	})
}

func (s *Service) List(ctx context.Context, p authz.Principal) ([]Resource, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.ResourceInventoryView, uuid.Nil); err != nil {
		return nil, err
	}
	principals := make([]pgtype.UUID, len(p.GranteeSet()))
	for i, id := range p.GranteeSet() {
		principals[i] = pg(id)
	}
	rows, err := q.ListAvailableConnectors(ctx, dbq.ListAvailableConnectorsParams{PrincipalIds: principals, GovernanceView: p.TenantRole == auth.RoleAdmin})
	if err != nil {
		return nil, err
	}
	out := make([]Resource, len(rows))
	for i, row := range rows {
		full, err := q.GetConnectorResource(ctx, row.ID)
		if err != nil {
			return nil, err
		}
		resource, err := s.loadResource(ctx, q, p, full, row.Capabilities, row.AgentCount, false)
		if err != nil {
			return nil, err
		}
		out[i] = resource
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, p authz.Principal, id uuid.UUID) (Resource, error) {
	q := dbq.New(s.db.Pool())
	row, err := q.GetConnectorResource(ctx, pg(id))
	if err != nil {
		return Resource{}, err
	}
	capabilities, err := authz.ResourceCapabilitiesForDetail(ctx, q, p, "connector", id)
	if err != nil {
		return Resource{}, err
	}
	return s.loadResource(ctx, q, p, row, capabilities, 0, true)
}

func (s *Service) loadResource(ctx context.Context, q *dbq.Queries, p authz.Principal, row dbq.ConnectorResource, capabilities []string, agentCount int32, detail bool) (Resource, error) {
	resource := Resource{Row: row, Capabilities: capabilities, AgentCount: agentCount}
	canView := slices.Contains(capabilities, authz.CapView)
	canManage := slices.Contains(capabilities, authz.CapManage)
	if canView && row.InterfaceDescriptor != nil {
		descriptor, err := ParseDescriptor(row.InterfaceDescriptor)
		if err != nil {
			return Resource{}, fmt.Errorf("decode persisted connector interface: %w", err)
		}
		resource.Commands, resource.Directories = descriptor.Commands, descriptor.Directories
	}
	if canView || canManage {
		names, err := q.ResolvePrincipalNames(ctx, []pgtype.UUID{row.OwnerPrincipalID})
		if err != nil {
			return Resource{}, err
		}
		if len(names) != 1 {
			return Resource{}, errors.New("connector owner principal has no display name")
		}
		resource.OwnerName = names[0].Name
		resource.OwnerKind, err = q.GetPrincipalKind(ctx, row.OwnerPrincipalID)
		if err != nil {
			return Resource{}, err
		}
	}
	if canView {
		var err error
		resource.ArtifactStatus, err = connectorArtifactStatus(ctx, q, row)
		if err != nil {
			return Resource{}, err
		}
	}
	if !detail {
		return resource, nil
	}
	if canManage {
		grantRows, err := q.ListConnectorGrantDetails(ctx, row.ID)
		if err != nil {
			return Resource{}, err
		}
		resource.Grants = make([]ResourceGrant, len(grantRows))
		for i, grant := range grantRows {
			resource.Grants[i] = ResourceGrant{
				ID: uuid.UUID(grant.ID.Bytes), GranteeID: uuid.UUID(grant.GranteeID.Bytes),
				GranteeName: grant.GranteeName, GranteeKind: grant.GranteeKind, Capabilities: grant.Capabilities,
			}
		}
	}
	if canView {
		consumerRows, err := q.ListConnectorConsumers(ctx, row.ID)
		if err != nil {
			return Resource{}, err
		}
		resource.Consumers = make([]Consumer, len(consumerRows))
		for i, consumer := range consumerRows {
			agentID := uuid.UUID(consumer.AgentID.Bytes)
			resource.Consumers[i] = Consumer{
				AgentID: agentID, AgentName: consumer.AgentName, AgentSlug: consumer.AgentSlug,
				NeedType: consumer.NeedType, NeedSlug: consumer.NeedSlug,
				CanAccessAgent: authz.Authorize(ctx, q, p, authz.AgentGet, agentID) == nil,
			}
		}
		resource.AgentCount = int32(len(resource.Consumers))
	}
	return resource, nil
}

func connectorArtifactStatus(ctx context.Context, q *dbq.Queries, row dbq.ConnectorResource) (ArtifactStatus, error) {
	status := ArtifactStatus{Freshness: "missing", UpdateStatus: "manual_update_required"}
	if row.ProtocolMajor.Valid && row.ProtocolMajor.Int32 != ProtocolMajor || row.Readiness == "incompatible_protocol" {
		status.UpdateStatus = "unsupported_protocol"
	}
	if row.ArtifactDigest.Valid {
		status.Freshness = "unknown"
	}
	latest, err := q.GetConnectorArtifactStatus(ctx, row.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return status, nil
	}
	if err != nil {
		return ArtifactStatus{}, err
	}
	status.LatestVersion = latest.ArtifactVersion
	status.LatestInterfaceHash = latest.InterfaceHash
	status.LatestArtifactCreated = latest.CreatedAt
	if latest.LatestFileDigest.Valid {
		status.LatestDigest = latest.LatestFileDigest.String
	}
	if status.UpdateStatus == "unsupported_protocol" {
		return status, nil
	}
	if latest.LatestFileDigest.Valid && row.ArtifactDigest.Valid && latest.LatestFileDigest.String == row.ArtifactDigest.String {
		status.Freshness, status.UpdateStatus = "current", "current"
		return status, nil
	}
	if !latest.InstalledArtifactSetID.Valid || !latest.LatestFileDigest.Valid {
		return status, nil
	}
	status.Freshness = "outdated"
	if latest.ProtocolMajor != ProtocolMajor {
		return status, nil
	}
	if row.InterfaceHash.Valid && latest.InterfaceHash == row.InterfaceHash.String {
		status.UpdateStatus = "update_available"
	} else if latest.InterfaceCompatible {
		status.UpdateStatus = "update_recommended"
	}
	return status, nil
}

func (s *Service) ResourceStatus(ctx context.Context, id uuid.UUID) (dbq.ConnectorResource, ArtifactStatus, error) {
	q := dbq.New(s.db.Pool())
	row, err := q.GetConnectorResource(ctx, pg(id))
	if err != nil {
		return dbq.ConnectorResource{}, ArtifactStatus{}, err
	}
	status, err := connectorArtifactStatus(ctx, q, row)
	return row, status, err
}

func (s *Service) SetLabels(ctx context.Context, p authz.Principal, id uuid.UUID, labels map[string]string) (dbq.ConnectorResource, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.ConnectorResource{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "connector", id); err != nil {
		return dbq.ConnectorResource{}, err
	}
	if err := authz.LockResource(ctx, q, "connector", id); err != nil {
		return dbq.ConnectorResource{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "connector", id); err != nil {
		return dbq.ConnectorResource{}, err
	}
	if len(labels) > 100 {
		return dbq.ConnectorResource{}, service.Detail(service.ErrInvalidInput, "at most 100 connector labels are allowed")
	}
	for key, value := range labels {
		if strings.TrimSpace(key) == "" || len(key) > 63 || len(value) > 256 {
			return dbq.ConnectorResource{}, service.Detail(service.ErrInvalidInput, "invalid connector label")
		}
	}
	raw, err := json.Marshal(labels)
	if err != nil {
		return dbq.ConnectorResource{}, err
	}
	row, err := q.SetConnectorLabels(ctx, dbq.SetConnectorLabelsParams{ID: pg(id), Labels: raw})
	if err != nil {
		return dbq.ConnectorResource{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.ConnectorResource{}, err
	}
	return row, nil
}

func validReadiness(value string) bool {
	switch value {
	case "offline", "starting", "needs_configuration", "incompatible_protocol", "unhealthy", "ready":
		return true
	default:
		return false
	}
}
