// Package hosts owns host enrollment, authentication, inventory, connector
// ownership, and durable host management work.
package hosts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	connectorjobssvc "github.com/airlockrun/airlock/service/connectorjobs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const (
	enrollmentTTL          = 10 * time.Minute
	enrollmentPollInterval = 3
	leaseDuration          = 45 * time.Second
	artifactURLTTL         = 10 * time.Minute
	defaultJobTimeout      = 30 * time.Minute
	hostHeartbeatTimeout   = 2 * time.Minute
)

var (
	ErrEnrollmentRateLimited = errors.New("host enrollment rate limit exceeded")
	ErrSlowDown              = errors.New("host enrollment polling too quickly")
)

type objectStore interface {
	PublicPresignDownloadURL(context.Context, string, string, time.Duration) (string, error)
}

type Service struct {
	db             *db.DB
	publicURL      string
	storageOrigins []string
	store          objectStore
	connectorJobs  *connectorjobssvc.Service
	secrets        secrets.Store
	logger         *zap.Logger
}

type Enrollment struct {
	DeviceSecret string
	UserCode     string
	VerifyURL    string
	ExpiresAt    time.Time
	PollInterval int32
}

type EnrollmentResult struct {
	Status     string
	HostID     uuid.UUID
	Credential string
}

type Identity struct {
	HostID       uuid.UUID
	CredentialID uuid.UUID
}

type Detail struct {
	Host         dbq.Host
	Capabilities []string
	OwnerName    string
	Connectors   []dbq.ConnectorResource
	Jobs         []dbq.HostManagementJob
}

type ActiveAttempt struct {
	JobID        uuid.UUID
	AttemptToken uuid.UUID
}

type ConnectorCancellation struct {
	ConnectorID  uuid.UUID
	JobID        uuid.UUID
	AttemptToken uuid.UUID
}

type InstallRequest struct {
	AgentID        uuid.UUID
	NeedSlug       string
	ArtifactFileID uuid.UUID
	DisplayName    string
	Settings       json.RawMessage
	Timeout        time.Duration
}

type artifactDelivery struct {
	InstallationID string          `json:"installationId,omitempty"`
	Settings       json.RawMessage `json:"settings,omitempty"`
	URL            string          `json:"url"`
	Filename       string          `json:"filename"`
	SHA256         string          `json:"sha256"`
	SizeBytes      int64           `json:"sizeBytes"`
	StorageOrigins []string        `json:"storageOrigins,omitempty"`
}

type artifactLineage struct {
	agentID       pgtype.UUID
	connectorSlug string
}

type observedInventorySlot struct {
	digest        string
	manifest      []byte
	manifestHash  string
	provenance    string
	state         string
	artifactSetID pgtype.UUID
	candidate     *dbq.ListObservedArtifactCandidatesRow
}

func New(database *db.DB, publicURL string, storageOrigins []string, store objectStore, connectorJobs *connectorjobssvc.Service, secretStore secrets.Store, logger *zap.Logger) *Service {
	if database == nil || store == nil || connectorJobs == nil || secretStore == nil || logger == nil {
		panic("hosts: nil dependency")
	}
	return &Service{
		db: database, publicURL: strings.TrimRight(publicURL, "/"),
		storageOrigins: slices.Clone(storageOrigins), store: store,
		connectorJobs: connectorJobs, secrets: secretStore, logger: logger,
	}
}

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func nullablePG(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil} }

func validateInfo(info protocol.HostInfo) error {
	if info.ProtocolVersion != protocol.HostProtocolVersion {
		return service.Detail(service.ErrConflict, "unsupported host protocol version %d", info.ProtocolVersion)
	}
	if strings.TrimSpace(info.Name) == "" || len(info.Name) > 256 || strings.TrimSpace(info.Version) == "" || len(info.Version) > 128 {
		return service.Detail(service.ErrInvalidInput, "host name and version are required")
	}
	if info.Platform != "linux" && info.Platform != "windows" && info.Platform != "darwin" {
		return service.Detail(service.ErrInvalidInput, "invalid host platform")
	}
	if info.Architecture != "amd64" && info.Architecture != "arm64" && !(info.Platform == "linux" && info.Architecture == "armv7") {
		return service.Detail(service.ErrInvalidInput, "invalid host architecture")
	}
	if info.AccessMode != protocol.RemoteAccessFull && info.AccessMode != protocol.RemoteAccessUpdateOnly && info.AccessMode != protocol.RemoteAccessNone {
		return service.Detail(service.ErrInvalidInput, "invalid host access mode")
	}
	return nil
}

func (s *Service) BeginEnrollment(ctx context.Context, clientIP string, info protocol.HostInfo) (Enrollment, error) {
	if err := validateInfo(info); err != nil {
		return Enrollment{}, err
	}
	allowed, err := dbq.New(s.db.Pool()).AllowHostEnrollment(ctx, clientIP)
	if err != nil {
		return Enrollment{}, err
	}
	if !allowed {
		return Enrollment{}, ErrEnrollmentRateLimited
	}
	deviceSecret, err := randomToken(32)
	if err != nil {
		return Enrollment{}, err
	}
	userCode, err := randomUserCode()
	if err != nil {
		return Enrollment{}, err
	}
	raw, err := json.Marshal(info)
	if err != nil {
		return Enrollment{}, err
	}
	expiresAt := time.Now().UTC().Add(enrollmentTTL)
	_, err = dbq.New(s.db.Pool()).CreateHostEnrollment(ctx, dbq.CreateHostEnrollmentParams{
		DeviceCodeHash: hash(deviceSecret), UserCodeHash: hash(normalizeUserCode(userCode)),
		UserCodeDisplay: userCode, HostInfo: raw, PollIntervalSeconds: enrollmentPollInterval,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{DeviceSecret: deviceSecret, UserCode: userCode, VerifyURL: s.publicURL + "/hosts/connect", ExpiresAt: expiresAt, PollInterval: enrollmentPollInterval}, nil
}

func (s *Service) InspectEnrollment(ctx context.Context, p authz.Principal, userCode string) (dbq.HostEnrollmentSession, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.HostEnrollmentApprove, uuid.Nil); err != nil {
		return dbq.HostEnrollmentSession{}, err
	}
	row, err := q.GetHostEnrollmentByUserCode(ctx, hash(normalizeUserCode(userCode)))
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.HostEnrollmentSession{}, service.ErrNotFound
	}
	return row, err
}

func (s *Service) ApproveEnrollment(ctx context.Context, p authz.Principal, userCode string) (dbq.HostEnrollmentSession, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.HostEnrollmentApprove, uuid.Nil); err != nil {
		return dbq.HostEnrollmentSession{}, err
	}
	row, err := q.ApproveHostEnrollment(ctx, dbq.ApproveHostEnrollmentParams{ApprovedByUserID: pg(p.UserID), UserCodeHash: hash(normalizeUserCode(userCode))})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.HostEnrollmentSession{}, service.Detail(service.ErrConflict, "host enrollment is not pending")
	}
	return row, err
}

func (s *Service) DenyEnrollment(ctx context.Context, p authz.Principal, userCode string) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.HostEnrollmentApprove, uuid.Nil); err != nil {
		return err
	}
	_, err := q.DenyHostEnrollment(ctx, hash(normalizeUserCode(userCode)))
	if errors.Is(err, pgx.ErrNoRows) {
		return service.Detail(service.ErrConflict, "host enrollment is not pending")
	}
	return err
}

func (s *Service) CompleteEnrollment(ctx context.Context, deviceSecret string) (EnrollmentResult, error) {
	if len(deviceSecret) < 32 || len(deviceSecret) > 128 {
		return EnrollmentResult{}, service.Detail(service.ErrInvalidInput, "device secret is invalid")
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return EnrollmentResult{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	enrollment, err := q.ClaimHostEnrollmentPoll(ctx, hash(deviceSecret))
	if errors.Is(err, pgx.ErrNoRows) {
		row, getErr := q.GetHostEnrollmentForPoll(ctx, hash(deviceSecret))
		if errors.Is(getErr, pgx.ErrNoRows) || getErr == nil && (!row.ExpiresAt.Valid || !row.ExpiresAt.Time.After(time.Now()) || row.ConsumedAt.Valid) {
			return EnrollmentResult{Status: "expired"}, tx.Commit(ctx)
		}
		if getErr != nil {
			return EnrollmentResult{}, getErr
		}
		return EnrollmentResult{}, ErrSlowDown
	}
	if err != nil {
		return EnrollmentResult{}, err
	}
	if enrollment.Status != "approved" {
		return EnrollmentResult{Status: enrollment.Status}, tx.Commit(ctx)
	}
	var info protocol.HostInfo
	if err := json.Unmarshal(enrollment.HostInfo, &info); err != nil || validateInfo(info) != nil {
		return EnrollmentResult{}, errors.New("host enrollment snapshot is invalid")
	}
	host, err := q.CreateHost(ctx, dbq.CreateHostParams{
		OwnerPrincipalID: enrollment.ApprovedByUserID,
		Name:             info.Name, Platform: info.Platform, Architecture: info.Architecture,
		AccessMode: string(info.AccessMode), Version: info.Version, ProtocolVersion: int32(info.ProtocolVersion),
		EnrolledByUserID: enrollment.ApprovedByUserID,
	})
	if err != nil {
		return EnrollmentResult{}, err
	}
	credential, selector, err := newHostCredential()
	if err != nil {
		return EnrollmentResult{}, err
	}
	if _, err := q.CreateHostCredential(ctx, dbq.CreateHostCredentialParams{HostID: host.ID, Selector: pg(selector), TokenHash: hash(credential)}); err != nil {
		return EnrollmentResult{}, err
	}
	if _, err := q.ConsumeHostEnrollment(ctx, dbq.ConsumeHostEnrollmentParams{HostID: host.ID, ID: enrollment.ID}); err != nil {
		return EnrollmentResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return EnrollmentResult{}, err
	}
	return EnrollmentResult{Status: "approved", HostID: uuid.UUID(host.ID.Bytes), Credential: credential}, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (Identity, error) {
	selector, ok := parseHostCredential(token)
	if !ok {
		return Identity{}, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	row, err := q.GetHostCredentialBySelector(ctx, pg(selector))
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, service.ErrUnauthorized
	}
	if err != nil {
		return Identity{}, err
	}
	presented := hash(token)
	if row.RevokedAt.Valid || row.HostLifecycle != "active" || len(row.TokenHash) != len(presented) || subtle.ConstantTimeCompare(row.TokenHash, presented) != 1 {
		return Identity{}, service.ErrUnauthorized
	}
	if affected, err := q.TouchHostCredential(ctx, row.ID); err != nil || affected != 1 {
		if err != nil {
			return Identity{}, err
		}
		return Identity{}, service.ErrUnauthorized
	}
	return Identity{HostID: uuid.UUID(row.HostID.Bytes), CredentialID: uuid.UUID(row.ID.Bytes)}, nil
}

func (s *Service) Sync(ctx context.Context, hostID uuid.UUID, request protocol.HostSyncRequest) (dbq.Host, error) {
	if err := validateInfo(request.Host); err != nil {
		return dbq.Host{}, err
	}
	if len(request.Connectors) > protocol.MaxHostedConnectors {
		return dbq.Host{}, service.Detail(service.ErrInvalidInput, "host reported too many connectors")
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.Host{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	host, err := q.SyncHost(ctx, dbq.SyncHostParams{
		Name: request.Host.Name, Platform: request.Host.Platform, Architecture: request.Host.Architecture,
		AccessMode: string(request.Host.AccessMode), Version: request.Host.Version,
		ProtocolVersion: int32(request.Host.ProtocolVersion), ID: pg(hostID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.Host{}, service.ErrUnauthorized
	}
	if err != nil {
		return dbq.Host{}, err
	}
	reported := make([]pgtype.UUID, 0, len(request.Connectors))
	seen := make(map[uuid.UUID]struct{}, len(request.Connectors))
	active := make([]ActiveAttempt, 0)
	for _, status := range request.Connectors {
		connectorID, err := uuid.Parse(status.InstallationID)
		if err != nil || connectorID == uuid.Nil || connectorID.String() != status.InstallationID {
			return dbq.Host{}, service.Detail(service.ErrInvalidInput, "host reported an invalid connector ID")
		}
		if _, duplicate := seen[connectorID]; duplicate {
			return dbq.Host{}, service.Detail(service.ErrInvalidInput, "host reported a connector more than once")
		}
		seen[connectorID] = struct{}{}
		if _, err := q.GetHostedConnector(ctx, dbq.GetHostedConnectorParams{ID: pg(connectorID), HostID: pg(hostID)}); errors.Is(err, pgx.ErrNoRows) {
			// Inventory mutation acknowledgement establishes the resource. Compact
			// status for a pending local installation must not block host liveness.
			continue
		} else if err != nil {
			return dbq.Host{}, err
		}
		if err := protocol.ValidateHostedConnectorManifest(status.Manifest); err != nil {
			return dbq.Host{}, service.Detail(service.ErrInvalidInput, "host connector manifest summary is invalid")
		}
		readiness := string(status.Readiness)
		if (readiness != "offline" && readiness != "starting" && readiness != "needs_configuration" && readiness != "incompatible_protocol" && readiness != "unhealthy" && readiness != "ready") || len(status.Error) > protocol.MaxHostedStatusErrorBytes {
			return dbq.Host{}, service.Detail(service.ErrInvalidInput, "host connector readiness is invalid")
		}
		_, err = q.SyncHostedConnector(ctx, dbq.SyncHostedConnectorParams{
			ProtocolMajor: pgtype.Int4{Int32: int32(status.Manifest.ProtocolMajor), Valid: true},
			ProtocolMinor: pgtype.Int4{Int32: int32(status.Manifest.ProtocolMinor), Valid: true},
			Features:      status.Manifest.Features, ArtifactVersion: pgtype.Text{String: status.Manifest.ArtifactVersion, Valid: true},
			ArtifactDigest: pgtype.Text{String: status.Manifest.ArtifactDigest, Valid: true}, InterfaceHash: pgtype.Text{String: status.Manifest.InterfaceHash, Valid: true},
			Readiness: readiness, ReadinessMessage: pgtype.Text{String: status.Error, Valid: status.Error != ""},
			ID: pg(connectorID), HostID: pg(hostID),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.Host{}, service.Detail(service.ErrForbidden, "connector %s does not belong to this host", connectorID)
		}
		if err != nil {
			return dbq.Host{}, err
		}
		reported = append(reported, pg(connectorID))
		for _, attempt := range status.ActiveAttempts {
			jobID, jobErr := uuid.Parse(attempt.JobID)
			token, tokenErr := uuid.Parse(attempt.AttemptToken)
			if jobErr != nil || tokenErr != nil {
				return dbq.Host{}, service.Detail(service.ErrInvalidInput, "host reported an invalid connector attempt")
			}
			active = append(active, ActiveAttempt{JobID: jobID, AttemptToken: token})
		}
	}
	if _, err := q.MarkMissingHostedConnectorsOffline(ctx, dbq.MarkMissingHostedConnectorsOfflineParams{HostID: pg(hostID), ReportedIds: reported}); err != nil {
		return dbq.Host{}, err
	}
	if err := renewConnectorAttempts(ctx, q, hostID, active); err != nil {
		return dbq.Host{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.Host{}, err
	}
	return host, nil
}

// ReconcileInventory applies one durable installation mutation under the
// shared connector lock protocol documented by connectors.LockResources.
func (s *Service) ReconcileInventory(ctx context.Context, hostID uuid.UUID, request protocol.HostConnectorInventoryMutationRequest) (protocol.HostConnectorInventoryMutationResponse, error) {
	if err := protocol.ValidateHostConnectorInventoryMutationRequest(request); err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrInvalidInput, "%v", err)
	}
	if request.Revision > math.MaxInt64 {
		return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrInvalidInput, "inventory revision exceeds the supported range")
	}
	connectorID, err := uuid.Parse(request.InstallationID)
	if err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrInvalidInput, "invalid connector installation ID")
	}
	requestRaw, err := json.Marshal(request)
	if err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	requestHash, err := protocol.HashJSON(requestRaw)
	if err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}

	artifactLock, err := s.db.AcquireAdvisoryLock(ctx, "connector-artifact-gc")
	if err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	defer artifactLock.Unlock()
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	host, err := q.LockHostForInventory(ctx, pg(hostID))
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.HostConnectorInventoryMutationResponse{}, service.ErrUnauthorized
	}
	if err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	current, err := q.GetHostedConnectorForInventory(ctx, pg(connectorID))
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	if exists && uuid.UUID(current.HostID.Bytes) != hostID {
		return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrForbidden, "connector installation belongs to another host")
	}
	if exists {
		currentRevision := uint64(current.InventoryRevision)
		switch {
		case request.Revision < currentRevision:
			return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrConflict, "inventory revision %d is stale; revision %d is already acknowledged", request.Revision, currentRevision)
		case request.Revision == currentRevision:
			if !current.InventoryMutationHash.Valid || current.InventoryMutationHash.String != requestHash {
				return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrConflict, "inventory revision %d conflicts with its acknowledged mutation", request.Revision)
			}
			origins := []string(nil)
			if request.Kind == protocol.HostConnectorMutationUpsert && current.Lifecycle == "active" {
				origins = slices.Clone(current.StorageOrigins)
			}
			return protocol.HostConnectorInventoryMutationResponse{InstallationID: request.InstallationID, AcknowledgedRevision: request.Revision, StorageOrigins: origins}, tx.Commit(ctx)
		}
		if current.Lifecycle == "revoked" && request.Kind == protocol.HostConnectorMutationUpsert {
			return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrConflict, "removed connector installation cannot be recreated")
		}
		groupIDs, err := q.ListConnectorInventoryGroupIDs(ctx, pg(connectorID))
		if err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
		for _, groupID := range groupIDs {
			if err := q.LockConnectorTargetGroup(ctx, groupID); err != nil {
				return protocol.HostConnectorInventoryMutationResponse{}, err
			}
		}
		if _, err := q.LockConnectorInventoryBindings(ctx, pg(connectorID)); err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
		if _, err := q.LockConnectorInventoryMemberships(ctx, pg(connectorID)); err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
		if _, err := q.LockConnectorInventoryReservations(ctx, pg(connectorID)); err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
	}

	revision := int64(request.Revision)
	mutationHash := pgtype.Text{String: requestHash, Valid: true}
	if request.Kind == protocol.HostConnectorMutationRemove {
		if !exists {
			return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrConflict, "cannot remove an unacknowledged connector installation")
		}
		if _, err := q.TombstoneConnectorInventory(ctx, dbq.TombstoneConnectorInventoryParams{ID: pg(connectorID), InventoryRevision: revision, InventoryMutationHash: mutationHash}); err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
		return protocol.HostConnectorInventoryMutationResponse{InstallationID: request.InstallationID, AcknowledgedRevision: request.Revision}, nil
	}

	var lineage *artifactLineage
	if exists && current.ActiveProvenance == "airlock" && current.ArtifactSetID.Valid {
		row, err := q.GetConnectorArtifactLineage(ctx, current.ArtifactSetID)
		if err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
		lineage = &artifactLineage{agentID: row.AgentID, connectorSlug: row.ConnectorSlug}
	}
	active, err := classifyObservedInventorySlot(ctx, q, host, *request.Active, lineage)
	if err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	if exists && current.ArtifactDigest.Valid && current.ArtifactDigest.String != active.digest {
		transition, err := q.HasActiveConnectorManagementTransition(ctx, pg(connectorID))
		if err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
		if transition {
			return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrConflict, "connector inventory transition is awaiting fenced management completion")
		}
	}
	rollback := observedInventorySlot{provenance: "none", state: "none"}
	rollbackLineage := lineage
	if active.candidate != nil {
		rollbackLineage = &artifactLineage{agentID: active.candidate.AgentID, connectorSlug: active.candidate.ConnectorSlug}
	}
	if request.Rollback != nil {
		rollback, err = classifyObservedInventorySlot(ctx, q, host, *request.Rollback, rollbackLineage)
		if err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
	}
	interfaceRaw, err := canonicalJSON(request.Active.Manifest.Interface)
	if err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	readiness := "starting"
	readinessMessage := "manual connector inventory reconciled; awaiting heartbeat"
	if active.state == "invalid" {
		readiness = "unhealthy"
		readinessMessage = "observed connector manifest conflicts with Airlock metadata for the measured digest"
	}

	if !exists {
		count, err := q.CountHostedConnectorsForHost(ctx, pg(hostID))
		if err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
		if count >= protocol.MaxHostedConnectors {
			return protocol.HostConnectorInventoryMutationResponse{}, service.Detail(service.ErrConflict, "host has reached the connector installation limit")
		}
		metadata := request.Active.Manifest.Interface
		serviceMode := pgtype.Text{}
		if active.candidate != nil {
			metadata.Kind = active.candidate.Kind
			metadata.ContractID = active.candidate.ContractID
			metadata.Name = active.candidate.Name
			metadata.Description = active.candidate.Description
			metadata.ArtifactVersion = active.candidate.ArtifactVersion
			interfaceRaw = active.candidate.InterfaceDescriptor
			serviceMode = active.candidate.ServiceMode
			readinessMessage = "connector inventory reconciled; awaiting heartbeat"
		}
		if _, err := q.CreateObservedConnectorInventory(ctx, dbq.CreateObservedConnectorInventoryParams{
			ID: pg(connectorID), HostID: pg(hostID), OwnerPrincipalID: host.OwnerPrincipalID,
			Kind: textValue(metadata.Kind), ContractID: textValue(metadata.ContractID), Name: textValue(metadata.Name),
			DisplayName: request.DisplayName, Description: textValue(metadata.Description),
			ProtocolMajor: int4(request.Active.Manifest.ProtocolMajor), ProtocolMinor: int4(request.Active.Manifest.ProtocolMinor),
			Features: request.Active.Manifest.Features, ArtifactVersion: textValue(metadata.ArtifactVersion), ActiveDigest: textValue(active.digest),
			InterfaceDescriptor: interfaceRaw, InterfaceHash: textValue(request.Active.Manifest.InterfaceHash),
			Readiness: readiness, ReadinessMessage: textValue(readinessMessage), StorageOrigins: slices.Clone(s.storageOrigins),
			ServiceMode: serviceMode, ActiveArtifactSetID: active.artifactSetID, RollbackArtifactSetID: rollback.artifactSetID,
			InventoryRevision: revision, InventoryMutationHash: mutationHash, ActiveProvenance: active.provenance,
			RollbackProvenance: rollback.provenance, ActiveObservationState: active.state, RollbackObservationState: rollback.state,
			ActiveManifest: active.manifest, ActiveManifestHash: textValue(active.manifestHash),
			RollbackDigest: nullableText(rollback.digest), RollbackManifest: rollback.manifest, RollbackManifestHash: nullableText(rollback.manifestHash),
		}); err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
	} else if active.state == "known" {
		if _, err := q.ReconcileKnownConnectorInventory(ctx, dbq.ReconcileKnownConnectorInventoryParams{
			ID: pg(connectorID), DisplayName: request.DisplayName, ActiveDigest: textValue(active.digest), ActiveArtifactSetID: active.artifactSetID,
			RollbackArtifactSetID: rollback.artifactSetID, InventoryRevision: revision, InventoryMutationHash: mutationHash,
			RollbackProvenance: rollback.provenance, RollbackObservationState: rollback.state,
			ActiveManifest: active.manifest, ActiveManifestHash: textValue(active.manifestHash),
			RollbackDigest: nullableText(rollback.digest), RollbackManifest: rollback.manifest, RollbackManifestHash: nullableText(rollback.manifestHash),
		}); err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
	} else {
		manifest := request.Active.Manifest
		if _, err := q.ReconcileManualConnectorInventory(ctx, dbq.ReconcileManualConnectorInventoryParams{
			ID: pg(connectorID), DisplayName: request.DisplayName, Kind: textValue(manifest.Interface.Kind),
			ContractID: textValue(manifest.Interface.ContractID), Name: textValue(manifest.Interface.Name), Description: textValue(manifest.Interface.Description),
			ProtocolMajor: int4(manifest.ProtocolMajor), ProtocolMinor: int4(manifest.ProtocolMinor), Features: manifest.Features,
			ArtifactVersion: textValue(manifest.Interface.ArtifactVersion), ActiveDigest: textValue(active.digest),
			InterfaceDescriptor: interfaceRaw, InterfaceHash: textValue(manifest.InterfaceHash), RollbackArtifactSetID: rollback.artifactSetID,
			InventoryRevision: revision, InventoryMutationHash: mutationHash, RollbackProvenance: rollback.provenance,
			ActiveObservationState: active.state, RollbackObservationState: rollback.state,
			ActiveManifest: active.manifest, ActiveManifestHash: textValue(active.manifestHash),
			RollbackDigest: nullableText(rollback.digest), RollbackManifest: rollback.manifest, RollbackManifestHash: nullableText(rollback.manifestHash),
			Readiness: readiness, ReadinessMessage: textValue(readinessMessage),
		}); err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
		if err := q.UnbindConnectorInventory(ctx, pg(connectorID)); err != nil {
			return protocol.HostConnectorInventoryMutationResponse{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return protocol.HostConnectorInventoryMutationResponse{}, err
	}
	return protocol.HostConnectorInventoryMutationResponse{
		InstallationID: request.InstallationID, AcknowledgedRevision: request.Revision,
		StorageOrigins: slices.Clone(s.storageOrigins),
	}, nil
}

func classifyObservedInventorySlot(ctx context.Context, q *dbq.Queries, host dbq.Host, artifact protocol.ObservedConnectorArtifact, lineage *artifactLineage) (observedInventorySlot, error) {
	manifest, err := canonicalJSON(artifact.Manifest)
	if err != nil {
		return observedInventorySlot{}, err
	}
	manifestHash, err := protocol.HashJSON(manifest)
	if err != nil {
		return observedInventorySlot{}, err
	}
	candidates, err := q.ListObservedArtifactCandidates(ctx, dbq.ListObservedArtifactCandidatesParams{
		Digest: artifact.MeasuredDigest, Platform: host.Platform + "-" + host.Architecture,
	})
	if err != nil {
		return observedInventorySlot{}, err
	}
	eligible := 0
	for i := range candidates {
		candidate := &candidates[i]
		if lineage != nil && (candidate.AgentID != lineage.agentID || candidate.ConnectorSlug != lineage.connectorSlug) {
			continue
		}
		eligible++
		match, err := observedManifestMatchesCandidate(artifact.Manifest, *candidate)
		if err != nil {
			return observedInventorySlot{}, err
		}
		if match {
			return observedInventorySlot{
				digest: artifact.MeasuredDigest, manifest: manifest, manifestHash: manifestHash,
				provenance: "airlock", state: "known", artifactSetID: candidate.ID, candidate: candidate,
			}, nil
		}
	}
	state := "manual"
	if eligible > 0 {
		state = "invalid"
	}
	return observedInventorySlot{digest: artifact.MeasuredDigest, manifest: manifest, manifestHash: manifestHash, provenance: "manual", state: state}, nil
}

func observedManifestMatchesCandidate(manifest protocol.Manifest, candidate dbq.ListObservedArtifactCandidatesRow) (bool, error) {
	if int32(manifest.ProtocolMajor) != candidate.ProtocolMajor || int32(manifest.ProtocolMinor) != candidate.ProtocolMinor ||
		!slices.Equal(manifest.Features, candidate.Features) || manifest.InterfaceHash != candidate.InterfaceHash ||
		manifest.Interface.Kind != candidate.Kind || manifest.Interface.ContractID != candidate.ContractID ||
		manifest.Interface.Name != candidate.Name || manifest.Interface.Description != candidate.Description ||
		manifest.Interface.ArtifactVersion != candidate.ArtifactVersion {
		return false, nil
	}
	interfaceRaw, err := canonicalJSON(manifest.Interface)
	if err != nil {
		return false, err
	}
	candidateInterface, err := protocol.CanonicalJSON(candidate.InterfaceDescriptor)
	if err != nil {
		return false, err
	}
	settingsRaw, err := canonicalJSON(manifest.Settings)
	if err != nil {
		return false, err
	}
	candidateSettings, err := protocol.CanonicalJSON(candidate.SettingsSchema)
	if err != nil {
		return false, err
	}
	targets := slices.Clone(manifest.Targets)
	sort.Strings(targets)
	return bytes.Equal(interfaceRaw, candidateInterface) && bytes.Equal(settingsRaw, candidateSettings) && slices.Equal(targets, candidate.Targets), nil
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return protocol.CanonicalJSON(raw)
}

func textValue(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: true}
}

func nullableText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}

func int4(value int) pgtype.Int4 {
	return pgtype.Int4{Int32: int32(value), Valid: true}
}

func (s *Service) List(ctx context.Context, p authz.Principal) ([]dbq.ListHostsRow, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.ResourceInventoryView, uuid.Nil); err != nil {
		return nil, err
	}
	principals := make([]pgtype.UUID, len(p.GranteeSet()))
	for i, id := range p.GranteeSet() {
		principals[i] = pg(id)
	}
	rows, err := q.ListHosts(ctx, dbq.ListHostsParams{PrincipalIds: principals, GovernanceView: p.TenantRole == auth.RoleAdmin})
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if !hostHeartbeatFresh(rows[i].LastSeenAt, time.Now()) {
			rows[i].Lifecycle = "offline"
		}
	}
	return rows, nil
}

func (s *Service) Get(ctx context.Context, p authz.Principal, hostID uuid.UUID) (Detail, error) {
	q := dbq.New(s.db.Pool())
	capabilities, err := authz.ResourceCapabilitiesForView(ctx, q, p, "host", hostID)
	if err != nil {
		return Detail{}, err
	}
	host, err := q.GetHost(ctx, pg(hostID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Detail{}, service.ErrNotFound
	}
	if err != nil {
		return Detail{}, err
	}
	if !hostHeartbeatFresh(host.LastSeenAt, time.Now()) {
		host.Lifecycle = "offline"
	}
	names, err := q.ResolvePrincipalNames(ctx, []pgtype.UUID{host.OwnerPrincipalID})
	if err != nil {
		return Detail{}, err
	}
	if len(names) != 1 {
		return Detail{}, errors.New("host owner principal has no display name")
	}
	connectors, err := q.ListHostedConnectors(ctx, pg(hostID))
	if err != nil {
		return Detail{}, err
	}
	jobs, err := q.ListHostManagementJobs(ctx, dbq.ListHostManagementJobsParams{HostID: pg(hostID), Lim: 200})
	return Detail{Host: host, Capabilities: capabilities, OwnerName: names[0].Name, Connectors: connectors, Jobs: jobs}, err
}

func (s *Service) GetJob(ctx context.Context, p authz.Principal, jobID uuid.UUID) (dbq.HostManagementJob, []dbq.HostManagementEvent, error) {
	q := dbq.New(s.db.Pool())
	job, err := q.GetHostManagementJob(ctx, pg(jobID))
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.HostManagementJob{}, nil, service.ErrNotFound
	}
	if err != nil {
		return dbq.HostManagementJob{}, nil, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "host", uuid.UUID(job.HostID.Bytes)); err != nil {
		return dbq.HostManagementJob{}, nil, err
	}
	if managementPayloadsObservable(job.Kind) {
		input, err := s.secrets.Get(ctx, managementSecretRef(jobID, "input"), job.SecretInput)
		if err != nil {
			return dbq.HostManagementJob{}, nil, err
		}
		job.InputPayload = json.RawMessage(input)
		if job.SecretOutput.Valid {
			output, err := s.secrets.Get(ctx, managementSecretRef(jobID, "output"), job.SecretOutput.String)
			if err != nil {
				return dbq.HostManagementJob{}, nil, err
			}
			job.OutputPayload = json.RawMessage(output)
		}
	}
	events, err := q.ListHostManagementEvents(ctx, job.ID)
	return job, events, err
}

func timeout(value time.Duration) (time.Duration, error) {
	if value == 0 {
		return defaultJobTimeout, nil
	}
	if value < time.Second || value > 24*time.Hour {
		return 0, service.Detail(service.ErrInvalidInput, "management timeout must be between one second and 24 hours")
	}
	return value, nil
}

func requireMode(host dbq.Host, kind string) error {
	if host.AccessMode == "full" || host.AccessMode == "update_only" && (kind == "connector_update" || kind == "connector_rollback") {
		return nil
	}
	return service.Detail(service.ErrConflict, "host reported %s local access; requested management is not allowed", host.AccessMode)
}

func hostHeartbeatFresh(lastSeen pgtype.Timestamptz, now time.Time) bool {
	return lastSeen.Valid && lastSeen.Time.After(now.Add(-hostHeartbeatTimeout))
}

func managementPayloadsObservable(kind string) bool {
	return kind != "connector_install" && kind != "connector_update"
}

func (s *Service) RequestShell(ctx context.Context, p authz.Principal, hostID uuid.UUID, input protocol.ShellInput, duration time.Duration) (dbq.HostManagementJob, error) {
	if strings.TrimSpace(input.Command) == "" || len(input.Command) > 65536 || len(input.Stdin) > 1<<20 {
		return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "shell command is required and must fit within limits")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	if len(raw) > protocol.MaxJobPayloadBytes {
		return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "shell request exceeds the management payload limit")
	}
	return s.enqueue(ctx, p, hostID, uuid.Nil, "shell", uuid.Nil, raw, duration, nil)
}

func (s *Service) RequestInstall(ctx context.Context, p authz.Principal, hostID uuid.UUID, request InstallRequest) (dbq.HostManagementJob, error) {
	request.NeedSlug, request.DisplayName = strings.TrimSpace(request.NeedSlug), strings.TrimSpace(request.DisplayName)
	if request.AgentID == uuid.Nil || request.ArtifactFileID == uuid.Nil || request.NeedSlug == "" || request.DisplayName == "" || len(request.DisplayName) > 256 {
		return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "agent, need, artifact file, and display name are required")
	}
	if len(request.Settings) == 0 {
		request.Settings = json.RawMessage(`{}`)
	}
	var settingsObject map[string]json.RawMessage
	if len(request.Settings) > protocol.MaxJobPayloadBytes || json.Unmarshal(request.Settings, &settingsObject) != nil || settingsObject == nil {
		return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "connector settings must be valid JSON within the connector payload limit")
	}
	duration, err := timeout(request.Timeout)
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	q := dbq.New(s.db.Pool())
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "host", hostID); err != nil {
		return dbq.HostManagementJob{}, err
	}
	if err := authz.Authorize(ctx, q, p, authz.ConnectorArtifactView, request.AgentID); err != nil {
		return dbq.HostManagementJob{}, err
	}
	lock, err := s.db.AcquireAdvisoryLock(ctx, "connector-artifact-gc")
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	defer lock.Unlock()
	return s.withLockedManagementHost(ctx, p, hostID, "connector_install", func(qtx *dbq.Queries, host dbq.Host) (dbq.HostManagementJob, error) {
		if err := authz.Authorize(ctx, qtx, p, authz.ConnectorArtifactView, request.AgentID); err != nil {
			return dbq.HostManagementJob{}, err
		}
		artifact, err := qtx.GetHostArtifactFile(ctx, pg(request.ArtifactFileID))
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (artifact.AgentID.Bytes != request.AgentID || artifact.Platform != host.Platform+"-"+host.Architecture) {
			return dbq.HostManagementJob{}, service.Detail(service.ErrNotFound, "artifact file is not retained for this host and agent")
		}
		if err != nil {
			return dbq.HostManagementJob{}, err
		}
		count, err := qtx.CountHostedConnectorsForHost(ctx, pg(hostID))
		if err != nil {
			return dbq.HostManagementJob{}, err
		}
		if count >= protocol.MaxHostedConnectors {
			return dbq.HostManagementJob{}, service.Detail(service.ErrConflict, "host has reached the connector installation limit")
		}
		connectorID, jobID := uuid.New(), uuid.New()
		connector, err := qtx.CreateHostedConnector(ctx, dbq.CreateHostedConnectorParams{
			ID: pg(connectorID), HostID: pg(hostID), OwnerPrincipalID: pg(p.UserID), DisplayName: request.DisplayName,
			StorageOrigins: slices.Clone(s.storageOrigins), NeedSlug: request.NeedSlug,
			ArtifactFileID: pg(request.ArtifactFileID), AgentID: pg(request.AgentID),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return dbq.HostManagementJob{}, service.Detail(service.ErrNotFound, "artifact file does not satisfy the connector need")
		}
		if err != nil {
			return dbq.HostManagementJob{}, err
		}
		input, _ := json.Marshal(struct {
			InstallationID string          `json:"installationId"`
			Settings       json.RawMessage `json:"settings"`
		}{InstallationID: connectorID.String(), Settings: request.Settings})
		secretInput, err := s.secrets.Put(ctx, managementSecretRef(jobID, "input"), string(input))
		if err != nil {
			return dbq.HostManagementJob{}, err
		}
		return qtx.InsertHostManagementJob(ctx, dbq.InsertHostManagementJobParams{
			ID: pg(jobID), HostID: pg(hostID), ConnectorID: connector.ID, RequestedByUserID: pg(p.UserID),
			Kind: "connector_install", ArtifactFileID: pg(request.ArtifactFileID), SecretInput: secretInput,
			DeadlineAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(duration), Valid: true},
		})
	})
}

func (s *Service) RequestUpdate(ctx context.Context, p authz.Principal, connectorID, artifactFileID uuid.UUID, settings json.RawMessage, duration time.Duration) (dbq.HostManagementJob, error) {
	if connectorID == uuid.Nil || artifactFileID == uuid.Nil {
		return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "connector and artifact file are required")
	}
	if len(settings) > 0 {
		var settingsObject map[string]json.RawMessage
		if len(settings) > protocol.MaxJobPayloadBytes || json.Unmarshal(settings, &settingsObject) != nil || settingsObject == nil {
			return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "connector settings must be valid JSON within the connector payload limit")
		}
	}
	q := dbq.New(s.db.Pool())
	connector, err := q.GetConnectorResource(ctx, pg(connectorID))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !connector.HostID.Valid {
		return dbq.HostManagementJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	hostID := uuid.UUID(connector.HostID.Bytes)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "host", hostID); err != nil {
		return dbq.HostManagementJob{}, err
	}
	lock, err := s.db.AcquireAdvisoryLock(ctx, "connector-artifact-gc")
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	defer lock.Unlock()
	artifact, err := q.GetHostArtifactFile(ctx, pg(artifactFileID))
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.HostManagementJob{}, service.Detail(service.ErrNotFound, "artifact file is not retained")
	}
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	if err := authz.Authorize(ctx, q, p, authz.ConnectorArtifactView, uuid.UUID(artifact.AgentID.Bytes)); err != nil {
		return dbq.HostManagementJob{}, err
	}
	raw, _ := json.Marshal(struct {
		InstallationID string          `json:"installationId"`
		Settings       json.RawMessage `json:"settings,omitempty"`
	}{connectorID.String(), settings})
	return s.enqueue(ctx, p, hostID, connectorID, "connector_update", artifactFileID, raw, duration, func(qtx *dbq.Queries, host dbq.Host, _ dbq.ConnectorResource) error {
		groupIDs, err := qtx.ListConnectorInventoryGroupIDs(ctx, pg(connectorID))
		if err != nil {
			return err
		}
		for _, groupID := range groupIDs {
			if err := qtx.LockConnectorTargetGroup(ctx, groupID); err != nil {
				return err
			}
		}
		if _, err := qtx.LockConnectorInventoryBindings(ctx, pg(connectorID)); err != nil {
			return err
		}
		if _, err := qtx.LockConnectorInventoryMemberships(ctx, pg(connectorID)); err != nil {
			return err
		}
		if _, err := qtx.LockConnectorInventoryReservations(ctx, pg(connectorID)); err != nil {
			return err
		}
		compatible, err := qtx.GetCompatibleHostUpdateArtifact(ctx, dbq.GetCompatibleHostUpdateArtifactParams{
			ArtifactFileID: pg(artifactFileID), ConnectorID: pg(connectorID), HostID: pg(hostID), Platform: host.Platform + "-" + host.Architecture,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return service.Detail(service.ErrNotFound, "artifact file is not a retained compatible update for this connector")
		} else if err != nil {
			return err
		}
		if err := authz.Authorize(ctx, qtx, p, authz.ConnectorArtifactView, uuid.UUID(compatible.AgentID.Bytes)); err != nil {
			return err
		}
		return nil
	})
}

func (s *Service) RequestRollback(ctx context.Context, p authz.Principal, connectorID uuid.UUID, duration time.Duration) (dbq.HostManagementJob, error) {
	if connectorID == uuid.Nil {
		return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "connector is required")
	}
	q := dbq.New(s.db.Pool())
	connector, err := q.GetConnectorResource(ctx, pg(connectorID))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !connector.HostID.Valid {
		return dbq.HostManagementJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	hostID := uuid.UUID(connector.HostID.Bytes)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "host", hostID); err != nil {
		return dbq.HostManagementJob{}, err
	}
	raw, _ := json.Marshal(struct {
		InstallationID string `json:"installationId"`
	}{connectorID.String()})
	return s.enqueue(ctx, p, hostID, connectorID, "connector_rollback", uuid.Nil, raw, duration, func(_ *dbq.Queries, _ dbq.Host, locked dbq.ConnectorResource) error {
		if !locked.RollbackArtifactSetID.Valid {
			return service.Detail(service.ErrConflict, "connector has no rollback artifact")
		}
		return nil
	})
}

func (s *Service) RequestRemove(ctx context.Context, p authz.Principal, connectorID uuid.UUID, duration time.Duration) (dbq.HostManagementJob, error) {
	q := dbq.New(s.db.Pool())
	connector, err := q.GetConnectorResource(ctx, pg(connectorID))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !connector.HostID.Valid {
		return dbq.HostManagementJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	hostID := uuid.UUID(connector.HostID.Bytes)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "host", hostID); err != nil {
		return dbq.HostManagementJob{}, err
	}
	raw, _ := json.Marshal(struct {
		InstallationID string `json:"installationId"`
	}{connectorID.String()})
	return s.enqueue(ctx, p, hostID, connectorID, "connector_remove", uuid.Nil, raw, duration, nil)
}

type managementValidator func(*dbq.Queries, dbq.Host, dbq.ConnectorResource) error

func (s *Service) enqueue(ctx context.Context, p authz.Principal, hostID, connectorID uuid.UUID, kind string, artifactFileID uuid.UUID, input json.RawMessage, duration time.Duration, validate managementValidator) (dbq.HostManagementJob, error) {
	duration, err := timeout(duration)
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	return s.withLockedManagementHost(ctx, p, hostID, kind, func(q *dbq.Queries, host dbq.Host) (dbq.HostManagementJob, error) {
		var connector dbq.ConnectorResource
		if connectorID != uuid.Nil {
			connector, err = q.GetConnectorResourceForUpdate(ctx, pg(connectorID))
			if errors.Is(err, pgx.ErrNoRows) || err == nil && (!connector.HostID.Valid || connector.HostID.Bytes != hostID || connector.Lifecycle != "active") {
				return dbq.HostManagementJob{}, service.ErrNotFound
			}
			if err != nil {
				return dbq.HostManagementJob{}, err
			}
		}
		if validate != nil {
			if err := validate(q, host, connector); err != nil {
				return dbq.HostManagementJob{}, err
			}
		}
		jobID := uuid.New()
		secretInput, err := s.secrets.Put(ctx, managementSecretRef(jobID, "input"), string(input))
		if err != nil {
			return dbq.HostManagementJob{}, err
		}
		return q.InsertHostManagementJob(ctx, dbq.InsertHostManagementJobParams{
			ID: pg(jobID), HostID: pg(hostID), ConnectorID: nullablePG(connectorID), RequestedByUserID: pg(p.UserID),
			Kind: kind, ArtifactFileID: nullablePG(artifactFileID), SecretInput: secretInput,
			DeadlineAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(duration), Valid: true},
		})
	})
}

func (s *Service) withLockedManagementHost(ctx context.Context, p authz.Principal, hostID uuid.UUID, kind string, insert func(*dbq.Queries, dbq.Host) (dbq.HostManagementJob, error)) (dbq.HostManagementJob, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "host", hostID); err != nil {
		return dbq.HostManagementJob{}, err
	}
	if err := authz.LockResource(ctx, q, "host", hostID); err != nil {
		return dbq.HostManagementJob{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "host", hostID); err != nil {
		return dbq.HostManagementJob{}, err
	}
	host, err := q.GetHost(ctx, pg(hostID))
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.HostManagementJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	if err := requireMode(host, kind); err != nil {
		return dbq.HostManagementJob{}, err
	}
	if !hostHeartbeatFresh(host.LastSeenAt, time.Now()) {
		return dbq.HostManagementJob{}, service.Detail(service.ErrConflict, "host heartbeat is stale; wait for the host to reconnect before requesting management")
	}
	job, err := insert(q, host)
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.HostManagementJob{}, err
	}
	return job, nil
}

func (s *Service) RenewManagementAttempts(ctx context.Context, hostID uuid.UUID, attempts []ActiveAttempt) error {
	if len(attempts) > protocol.MaxActiveAttempts {
		return service.Detail(service.ErrInvalidInput, "host reported too many management attempts")
	}
	q := dbq.New(s.db.Pool())
	seen := make(map[uuid.UUID]struct{}, len(attempts))
	for _, attempt := range attempts {
		if attempt.JobID == uuid.Nil || attempt.AttemptToken == uuid.Nil {
			return service.Detail(service.ErrInvalidInput, "host reported an invalid management attempt")
		}
		if _, duplicate := seen[attempt.JobID]; duplicate {
			return service.Detail(service.ErrInvalidInput, "host repeated a management attempt")
		}
		seen[attempt.JobID] = struct{}{}
		if _, err := q.RenewHostManagementAttempt(ctx, dbq.RenewHostManagementAttemptParams{
			LeaseSeconds: int32(leaseDuration.Seconds()), JobID: pg(attempt.JobID), HostID: pg(hostID), AttemptToken: pg(attempt.AttemptToken),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) RenewConnectorAttempts(ctx context.Context, hostID uuid.UUID, attempts []ActiveAttempt) error {
	return renewConnectorAttempts(ctx, dbq.New(s.db.Pool()), hostID, attempts)
}

func renewConnectorAttempts(ctx context.Context, q *dbq.Queries, hostID uuid.UUID, attempts []ActiveAttempt) error {
	if len(attempts) > protocol.MaxActiveAttempts {
		return service.Detail(service.ErrInvalidInput, "host reported too many connector attempts")
	}
	seen := make(map[uuid.UUID]struct{}, len(attempts))
	for _, attempt := range attempts {
		if attempt.JobID == uuid.Nil || attempt.AttemptToken == uuid.Nil {
			return service.Detail(service.ErrInvalidInput, "host reported an invalid connector attempt")
		}
		if _, duplicate := seen[attempt.JobID]; duplicate {
			return service.Detail(service.ErrInvalidInput, "host repeated a connector attempt")
		}
		seen[attempt.JobID] = struct{}{}
		if _, err := q.RenewConnectorJobAttemptForHost(ctx, dbq.RenewConnectorJobAttemptForHostParams{
			LeaseSeconds: int32(leaseDuration.Seconds()), JobID: pg(attempt.JobID), HostID: pg(hostID), AttemptToken: pg(attempt.AttemptToken),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ClaimWork(ctx context.Context, hostID uuid.UUID, claimConnector bool) (*protocol.HostWork, error) {
	q := dbq.New(s.db.Pool())
	if _, err := q.FailExpiredHostManagementJobs(ctx, 100); err != nil {
		return nil, err
	}
	if _, err := q.ExpireHostManagementAttempts(ctx, 100); err != nil {
		return nil, err
	}
	management, err := q.ClaimHostManagementJob(ctx, dbq.ClaimHostManagementJobParams{HostID: pg(hostID), LeaseSeconds: int32(leaseDuration.Seconds())})
	if err == nil {
		plaintext, secretErr := s.secrets.Get(ctx, managementSecretRef(uuid.UUID(management.ID.Bytes), "input"), management.SecretInput)
		if secretErr != nil {
			return nil, secretErr
		}
		input := json.RawMessage(plaintext)
		if management.ArtifactFileID.Valid {
			artifact, artifactErr := q.GetHostArtifactFile(ctx, management.ArtifactFileID)
			if artifactErr != nil {
				return nil, artifactErr
			}
			url, artifactErr := s.store.PublicPresignDownloadURL(ctx, artifact.ObjectKey, artifact.Filename, artifactURLTTL)
			if artifactErr != nil {
				return nil, artifactErr
			}
			var persisted struct {
				InstallationID string          `json:"installationId"`
				Settings       json.RawMessage `json:"settings"`
			}
			if err := json.Unmarshal(input, &persisted); err != nil {
				return nil, err
			}
			input, _ = json.Marshal(artifactDelivery{
				InstallationID: persisted.InstallationID, Settings: persisted.Settings,
				URL: url, Filename: artifact.Filename, SHA256: artifact.Digest, SizeBytes: artifact.SizeBytes,
				StorageOrigins: slices.Clone(s.storageOrigins),
			})
		}
		return &protocol.HostWork{
			Kind: protocol.HostWorkKind(management.Kind), ConnectorID: uuid.UUID(management.ConnectorID.Bytes).String(),
			ManagementJob: &protocol.HostManagementJob{
				JobID: uuid.UUID(management.ID.Bytes).String(), AttemptToken: uuid.UUID(management.AttemptToken.Bytes).String(),
				Input: input, Deadline: management.DeadlineAt.Time,
			},
		}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if !claimConnector {
		return nil, nil
	}
	if _, err := q.FailExpiredConnectorJobs(ctx, 100); err != nil {
		return nil, err
	}
	if _, err := q.ExpireConnectorJobAttempts(ctx, 100); err != nil {
		return nil, err
	}
	connector, err := q.ClaimConnectorJobForHost(ctx, dbq.ClaimConnectorJobForHostParams{HostID: pg(hostID), LeaseSeconds: int32(leaseDuration.Seconds())})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &protocol.HostWork{
		Kind: protocol.HostWorkConnectorJob, ConnectorID: uuid.UUID(connector.ConnectorID.Bytes).String(),
		ConnectorJob: &protocol.JobRequest{
			JobID: uuid.UUID(connector.ID.Bytes).String(), AttemptToken: uuid.UUID(connector.AttemptToken.Bytes).String(),
			IdempotencyID: uuid.UUID(connector.IdempotencyKey.Bytes).String(), Kind: protocol.JobKind(connector.OperationKind),
			Operation: connector.OperationName, Revision: int(connector.OperationRevision), Mode: protocol.CommandMode(connector.Mode),
			InputSchemaHash: connector.InputSchemaHash, OutputSchemaHash: connector.OutputSchemaHash,
			Input: connector.InputPayload, Deadline: connector.DeadlineAt.Time,
		},
	}, nil
}

func (s *Service) WaitForWork(ctx context.Context, hostID uuid.UUID, claimConnector bool, maximum time.Duration) (*protocol.HostWork, error) {
	if maximum <= 0 || maximum > 30*time.Second {
		maximum = 25 * time.Second
	}
	if work, err := s.ClaimWork(ctx, hostID, claimConnector); err != nil || work != nil {
		return work, err
	}
	conn, err := s.db.Pool().Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN airlock_host_work"); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "LISTEN airlock_connector_dispatch"); err != nil {
		return nil, err
	}
	defer conn.Exec(context.Background(), "UNLISTEN *")
	if work, err := s.ClaimWork(ctx, hostID, claimConnector); err != nil || work != nil {
		return work, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, maximum)
	defer cancel()
	for {
		_, err := conn.Conn().WaitForNotification(waitCtx)
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if work, err := s.ClaimWork(ctx, hostID, claimConnector); err != nil || work != nil {
			return work, err
		}
	}
}

func (s *Service) AppendManagementEvent(ctx context.Context, hostID, jobID uuid.UUID, event protocol.HostManagementEvent) (dbq.AppendHostManagementEventRow, error) {
	token, err := uuid.Parse(event.AttemptToken)
	if err != nil || event.Sequence <= 0 || strings.TrimSpace(event.Phase) == "" || len(event.Phase) > 128 || len(event.Message) > 65536 || event.Time.IsZero() {
		return dbq.AppendHostManagementEventRow{}, service.Detail(service.ErrInvalidInput, "invalid host management event")
	}
	eventTime := event.Time.UTC().Truncate(time.Microsecond)
	row, err := dbq.New(s.db.Pool()).AppendHostManagementEvent(ctx, dbq.AppendHostManagementEventParams{
		JobID: pg(jobID), AttemptToken: pg(token), HostID: pg(hostID), AttemptSequence: event.Sequence,
		Phase: event.Phase, Message: event.Message, EventTime: pgtype.Timestamptz{Time: eventTime, Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.AppendHostManagementEventRow{}, service.Detail(service.ErrConflict, "host management lease is stale")
	}
	if err == nil && (row.Phase != event.Phase || row.Message != event.Message || !row.EventTime.Time.Equal(eventTime)) {
		return dbq.AppendHostManagementEventRow{}, service.Detail(service.ErrConflict, "management event sequence was reused with different content")
	}
	return row, err
}

func (s *Service) CompleteManagement(ctx context.Context, hostID, jobID uuid.UUID, completion protocol.HostManagementCompletion) (dbq.HostManagementJob, error) {
	if completion.JobID != "" && completion.JobID != jobID.String() {
		return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "management completion job ID does not match request path")
	}
	token, err := uuid.Parse(completion.AttemptToken)
	if err != nil || len(completion.Output) > 1<<20 || len(completion.Output) > 0 && !json.Valid(completion.Output) || len(completion.Error) > 65536 {
		return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "invalid host management completion")
	}
	succeeded := completion.Status == "success"
	if !succeeded && completion.Status != "error" && completion.Status != "canceled" && completion.Status != "timeout" {
		return dbq.HostManagementJob{}, service.Detail(service.ErrInvalidInput, "invalid host management completion status")
	}
	output := completion.Output
	if succeeded && len(output) == 0 {
		output = json.RawMessage(`{}`)
	}
	completionStatus := map[string]string{"success": "succeeded", "error": "failed", "canceled": "cancelled", "timeout": "timed_out"}[completion.Status]
	query := dbq.New(s.db.Pool())
	if existing, replay, err := s.completedManagementReplay(ctx, query, hostID, jobID, token, completionStatus, output, completion.Error); err != nil || replay {
		return existing, err
	}
	secretOutput := ""
	if succeeded {
		secretOutput, err = s.secrets.Put(ctx, managementSecretRef(jobID, "output"), string(output))
		if err != nil {
			return dbq.HostManagementJob{}, err
		}
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	row, err := q.CompleteHostManagementJob(ctx, dbq.CompleteHostManagementJobParams{
		JobID: pg(jobID), AttemptToken: pg(token), HostID: pg(hostID), Succeeded: succeeded,
		ErrorMessage: completion.Error, SecretOutput: secretOutput, CompletionStatus: completionStatus,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if existing, replay, replayErr := s.completedManagementReplay(ctx, query, hostID, jobID, token, completionStatus, output, completion.Error); replayErr != nil || replay {
			return existing, replayErr
		}
		return dbq.HostManagementJob{}, service.Detail(service.ErrConflict, "host management lease is stale")
	}
	if err != nil {
		return dbq.HostManagementJob{}, err
	}
	if succeeded && row.Kind == "connector_remove" {
		if affected, err := q.FinalizeConnectorRemoval(ctx, row.ConnectorID); err != nil || affected != 1 {
			if err != nil {
				return dbq.HostManagementJob{}, err
			}
			return dbq.HostManagementJob{}, errors.New("completed connector removal has no installation")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.HostManagementJob{}, err
	}
	return dbq.HostManagementJob(row), nil
}

func (s *Service) completedManagementReplay(ctx context.Context, q *dbq.Queries, hostID, jobID, token uuid.UUID, status string, output json.RawMessage, completionError string) (dbq.HostManagementJob, bool, error) {
	job, err := q.GetCompletedHostManagementJobForAttempt(ctx, dbq.GetCompletedHostManagementJobForAttemptParams{JobID: pg(jobID), HostID: pg(hostID), AttemptToken: pg(token)})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.HostManagementJob{}, false, nil
	}
	if err != nil {
		return dbq.HostManagementJob{}, false, err
	}
	if job.Status != status {
		if job.Status == "timed_out" {
			return dbq.HostManagementJob{}, false, nil
		}
		return dbq.HostManagementJob{}, false, service.Detail(service.ErrConflict, "host management completion conflicts with its recorded outcome")
	}
	if job.ErrorMessage.String != completionError {
		return dbq.HostManagementJob{}, false, service.Detail(service.ErrConflict, "host management completion conflicts with its recorded outcome")
	}
	if status == "succeeded" {
		plaintext, err := s.secrets.Get(ctx, managementSecretRef(jobID, "output"), job.SecretOutput.String)
		if err != nil {
			return dbq.HostManagementJob{}, false, err
		}
		if plaintext != string(output) {
			return dbq.HostManagementJob{}, false, service.Detail(service.ErrConflict, "host management completion conflicts with its recorded outcome")
		}
	}
	return job, true, nil
}

func (s *Service) AppendConnectorEvent(ctx context.Context, hostID, connectorID, jobID uuid.UUID, event protocol.JobEvent) error {
	if _, err := dbq.New(s.db.Pool()).GetHostedConnectorAnyLifecycle(ctx, dbq.GetHostedConnectorAnyLifecycleParams{ID: pg(connectorID), HostID: pg(hostID)}); errors.Is(err, pgx.ErrNoRows) {
		return service.ErrForbidden
	} else if err != nil {
		return err
	}
	token, err := uuid.Parse(event.AttemptToken)
	if err != nil {
		return service.Detail(service.ErrInvalidInput, "invalid connector attempt token")
	}
	payload, _ := json.Marshal(event)
	_, err = s.connectorJobs.AppendEvent(ctx, connectorID, jobID, token, event.Sequence, "progress", payload)
	return err
}

func (s *Service) CompleteConnector(ctx context.Context, hostID, connectorID, jobID uuid.UUID, completion protocol.JobCompletion) (dbq.ConnectorJob, error) {
	if _, err := dbq.New(s.db.Pool()).GetHostedConnectorAnyLifecycle(ctx, dbq.GetHostedConnectorAnyLifecycleParams{ID: pg(connectorID), HostID: pg(hostID)}); errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.ErrForbidden
	} else if err != nil {
		return dbq.ConnectorJob{}, err
	}
	token, err := uuid.Parse(completion.AttemptToken)
	if err != nil {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "invalid connector attempt token")
	}
	succeeded := completion.Status == "success"
	if !succeeded && completion.Status != "error" && completion.Status != "canceled" && completion.Status != "timeout" {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "invalid connector completion status")
	}
	return s.connectorJobs.Complete(ctx, connectorID, jobID, token, succeeded, completion.Output, completion.Status, completion.Error)
}

func (s *Service) Cancellations(ctx context.Context, hostID uuid.UUID) ([]ConnectorCancellation, error) {
	rows, err := dbq.New(s.db.Pool()).ListConnectorCancellationsForHost(ctx, pg(hostID))
	if err != nil {
		return nil, err
	}
	out := make([]ConnectorCancellation, len(rows))
	for i, row := range rows {
		out[i] = ConnectorCancellation{ConnectorID: uuid.UUID(row.ConnectorID.Bytes), JobID: uuid.UUID(row.JobID.Bytes), AttemptToken: uuid.UUID(row.AttemptToken.Bytes)}
	}
	return out, nil
}

func hash(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func newHostCredential() (string, uuid.UUID, error) {
	selector := uuid.New()
	secret, err := randomToken(32)
	if err != nil {
		return "", uuid.Nil, err
	}
	return "ahc_" + strings.ReplaceAll(selector.String(), "-", "") + "." + secret, selector, nil
}

func parseHostCredential(token string) (uuid.UUID, bool) {
	if len(token) < 80 || !strings.HasPrefix(token, "ahc_") {
		return uuid.Nil, false
	}
	parts := strings.Split(token[4:], ".")
	if len(parts) != 2 || len(parts[0]) != 32 {
		return uuid.Nil, false
	}
	selector, err := uuid.Parse(parts[0])
	return selector, err == nil
}

func normalizeUserCode(value string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(value)))
}

func managementSecretRef(jobID uuid.UUID, field string) string {
	return "host-management/" + jobID.String() + "/" + field
}

func randomUserCode() (string, error) {
	const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i := range raw {
		raw[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return fmt.Sprintf("%s-%s", raw[:4], raw[4:]), nil
}
