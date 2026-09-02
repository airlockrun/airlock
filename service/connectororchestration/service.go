// Package connectororchestration owns static target groups and persisted
// multi-target connector command orchestration.
package connectororchestration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	connectorssvc "github.com/airlockrun/airlock/service/connectors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type Service struct {
	db     *db.DB
	logger *zap.Logger
}

type CreateRequest struct {
	AgentID        uuid.UUID
	NeedSlug       string
	RequestID      uuid.UUID
	GroupID        uuid.UUID
	Command        string
	Input          json.RawMessage
	Strategy       string
	OfflinePolicy  string
	MaxConcurrency int32
	BatchSize      int32
	CanaryCount    int32
	Quorum         int32
	Deadline       time.Time
	ResourceIDs    []uuid.UUID
	Labels         map[string]string
	Revision       int32
	Mode           string
	InputHash      string
	OutputHash     string
}

type Detail struct {
	Orchestration dbq.ConnectorOrchestration
	Jobs          []dbq.ConnectorJob
}

type Group struct {
	Row              dbq.ConnectorTargetGroup
	MemberCount      int32
	ReadyMemberCount int32
	Capabilities     []string
}

type CreateGroupRequest struct {
	AgentID      uuid.UUID
	NeedSlug     string
	Name         string
	Description  string
	ConnectorIDs []uuid.UUID
}

func New(database *db.DB, logger *zap.Logger) *Service {
	if database == nil || logger == nil {
		panic("connectororchestration: nil dependency")
	}
	return &Service{db: database, logger: logger}
}

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func (s *Service) CreateGroup(ctx context.Context, p authz.Principal, request CreateGroupRequest) (Group, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Description = strings.TrimSpace(request.Description)
	request.NeedSlug = strings.TrimSpace(request.NeedSlug)
	if request.AgentID == uuid.Nil || request.Name == "" || request.NeedSlug == "" || len(request.Name) > 256 || len(request.Description) > 4096 || len(request.ConnectorIDs) == 0 || len(request.ConnectorIDs) > 256 {
		return Group{}, service.Detail(service.ErrInvalidInput, "agent, connector need, name, and initial members are required")
	}
	seen := make(map[uuid.UUID]struct{}, len(request.ConnectorIDs))
	for _, connectorID := range request.ConnectorIDs {
		if connectorID == uuid.Nil {
			return Group{}, service.Detail(service.ErrInvalidInput, "valid initial connector IDs are required")
		}
		if _, ok := seen[connectorID]; ok {
			return Group{}, service.Detail(service.ErrInvalidInput, "initial connector IDs must be unique")
		}
		seen[connectorID] = struct{}{}
	}

	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return Group{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(request.AgentID)); err != nil {
		return Group{}, notFound(err)
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentConnectors, request.AgentID); err != nil {
		return Group{}, err
	}
	if err := authz.Authorize(ctx, q, p, authz.ConnectorGroupManage, uuid.Nil); err != nil {
		return Group{}, err
	}
	for _, connectorID := range request.ConnectorIDs {
		if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, "connector", connectorID); err != nil {
			return Group{}, err
		}
	}
	lockedConnectors, err := connectorssvc.LockResources(ctx, q, request.ConnectorIDs)
	if err != nil {
		return Group{}, notFound(err)
	}
	for _, connectorID := range request.ConnectorIDs {
		if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, "connector", connectorID); err != nil {
			return Group{}, err
		}
	}
	need, err := q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams{AgentID: pg(request.AgentID), Type: "connector", Slug: request.NeedSlug})
	if err != nil {
		return Group{}, notFound(err)
	}
	spec, err := connectorssvc.ParseNeedSpec(need.Spec)
	if err != nil {
		return Group{}, service.Detail(service.ErrConflict, "%v", err)
	}
	if !spec.Multiple {
		return Group{}, service.Detail(service.ErrInvalidInput, "connector need is not multi-target")
	}
	row, err := q.CreateConnectorTargetGroup(ctx, dbq.CreateConnectorTargetGroupParams{
		OwnerPrincipalID: pg(p.UserID), Name: request.Name, Description: request.Description, ContractID: spec.ContractID,
	})
	if err != nil {
		return Group{}, err
	}
	ready := int32(0)
	for position, connectorID := range request.ConnectorIDs {
		connector := lockedConnectors[connectorID]
		descriptor, err := connectorssvc.ParseDescriptor(connector.InterfaceDescriptor)
		if connector.Lifecycle != "active" || err != nil || connectorssvc.Compatible(spec, descriptor) != nil {
			return Group{}, service.Detail(service.ErrConflict, "initial connector %s does not satisfy the complete connector need", connectorID)
		}
		if connector.Readiness == "ready" {
			ready++
		}
		if err := q.AddConnectorTargetGroupMember(ctx, dbq.AddConnectorTargetGroupMemberParams{GroupID: row.ID, ConnectorID: pg(connectorID), Position: int32(position)}); err != nil {
			return Group{}, err
		}
	}
	if ready == 0 {
		return Group{}, service.Detail(service.ErrConflict, "target group requires at least one ready compatible initial member")
	}
	if err := tx.Commit(ctx); err != nil {
		return Group{}, err
	}
	return Group{Row: row, MemberCount: int32(len(request.ConnectorIDs)), ReadyMemberCount: ready}, nil
}

func (s *Service) ListGroups(ctx context.Context, p authz.Principal) ([]Group, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.ConnectorGroupManage, uuid.Nil); err != nil {
		return nil, err
	}
	principals := make([]pgtype.UUID, len(p.GranteeSet()))
	for i, id := range p.GranteeSet() {
		principals[i] = pg(id)
	}
	rows, err := q.ListConnectorTargetGroups(ctx, dbq.ListConnectorTargetGroupsParams{PrincipalIds: principals, GovernanceView: p.TenantRole == auth.RoleAdmin})
	if err != nil {
		return nil, err
	}
	groups := make([]Group, len(rows))
	for i, row := range rows {
		groups[i] = Group{
			Row: dbq.ConnectorTargetGroup{
				ID: row.ID, OwnerPrincipalID: row.OwnerPrincipalID, Name: row.Name,
				Description: row.Description, ContractID: row.ContractID,
				CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
			},
			MemberCount: row.MemberCount, ReadyMemberCount: row.ReadyMemberCount,
			Capabilities: row.Capabilities,
		}
	}
	return groups, nil
}

// Existing fleet mutations use the shared protocol documented by
// connectors.LockResources.
func (s *Service) AddGroupMember(ctx context.Context, p authz.Principal, groupID, connectorID uuid.UUID, position int32) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.Authorize(ctx, q, p, authz.ConnectorGroupManage, uuid.Nil); err != nil {
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "connector_target_group", groupID); err != nil {
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, "connector", connectorID); err != nil {
		return err
	}
	locked, err := connectorssvc.LockResources(ctx, q, []uuid.UUID{connectorID})
	if err != nil {
		return notFound(err)
	}
	connector := locked[connectorID]
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceBind, "connector", connectorID); err != nil {
		return err
	}
	if err := authz.LockResource(ctx, q, "connector_target_group", groupID); err != nil {
		return notFound(err)
	}
	group, err := q.GetConnectorTargetGroup(ctx, pg(groupID))
	if err != nil {
		return notFound(err)
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "connector_target_group", groupID); err != nil {
		return err
	}
	if connector.Lifecycle != "active" {
		return service.Detail(service.ErrConflict, "connector must be active before it can join a target group")
	}
	descriptor, err := connectorssvc.ParseDescriptor(connector.InterfaceDescriptor)
	if err != nil {
		return service.Detail(service.ErrConflict, "connector has not published a valid interface")
	}
	if descriptor.ContractID != group.ContractID {
		return service.Detail(service.ErrInvalidInput, "connector contract ID does not match the target group")
	}
	need, err := q.GetBoundNeedForConnectorTargetGroup(ctx, pg(groupID))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	bound := err == nil
	if bound {
		spec, err := connectorssvc.ParseNeedSpec(need.Spec)
		if err != nil {
			return service.Detail(service.ErrConflict, "%v", err)
		}
		if err := connectorssvc.Compatible(spec, descriptor); err != nil {
			return service.Detail(service.ErrConflict, "connector does not satisfy the bound target-group need: %v", err)
		}
	}
	_, memberErr := q.GetConnectorTargetGroupMember(ctx, dbq.GetConnectorTargetGroupMemberParams{GroupID: pg(groupID), ConnectorID: pg(connectorID)})
	existing := memberErr == nil
	if memberErr != nil && !errors.Is(memberErr, pgx.ErrNoRows) {
		return memberErr
	}
	if existing && bound {
		reservation, err := q.GetConnectorReservationForUpdate(ctx, pg(connectorID))
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return service.Detail(service.ErrConflict, "bound target-group member is missing its reservation")
			}
			return err
		}
		if reservation.NeedID != need.ID || reservation.ConnectorTargetGroupID != pg(groupID) {
			return service.Detail(service.ErrConflict, "bound target-group member reservation does not match the group need")
		}
	}
	if err := q.AddConnectorTargetGroupMember(ctx, dbq.AddConnectorTargetGroupMemberParams{GroupID: pg(groupID), ConnectorID: pg(connectorID), Position: position}); err != nil {
		return err
	}
	if bound && !existing {
		if err := q.ReserveAddedConnectorTargetGroupMember(ctx, dbq.ReserveAddedConnectorTargetGroupMemberParams{ConnectorID: pg(connectorID), NeedID: need.ID, GroupID: pg(groupID)}); err != nil {
			if reservationConflict(err) {
				return service.Detail(service.ErrConflict, "connector is already reserved by another need")
			}
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) RemoveGroupMember(ctx context.Context, p authz.Principal, groupID, connectorID uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.Authorize(ctx, q, p, authz.ConnectorGroupManage, uuid.Nil); err != nil {
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "connector_target_group", groupID); err != nil {
		return err
	}
	if _, err := q.GetConnectorResourceForUpdate(ctx, pg(connectorID)); err != nil {
		return notFound(err)
	}
	if err := authz.LockResource(ctx, q, "connector_target_group", groupID); err != nil {
		return notFound(err)
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "connector_target_group", groupID); err != nil {
		return err
	}
	need, err := q.GetBoundNeedForConnectorTargetGroup(ctx, pg(groupID))
	if err == nil {
		count, err := q.CountNonterminalConnectorJobsForNeedConnector(ctx, dbq.CountNonterminalConnectorJobsForNeedConnectorParams{NeedID: need.ID, ConnectorID: pg(connectorID)})
		if err != nil {
			return err
		}
		if count != 0 {
			return service.Detail(service.ErrConflict, "connector has nonterminal target-group work; cancel or complete it before removal")
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	affected, err := q.RemoveConnectorTargetGroupMember(ctx, dbq.RemoveConnectorTargetGroupMemberParams{GroupID: pg(groupID), ConnectorID: pg(connectorID)})
	if err != nil {
		return err
	}
	if affected != 1 {
		return service.ErrNotFound
	}
	return tx.Commit(ctx)
}

func (s *Service) Create(ctx context.Context, p authz.Principal, request CreateRequest) (Detail, error) {
	return s.create(ctx, &p, request)
}

func (s *Service) CreateFromAgent(ctx context.Context, request CreateRequest) (Detail, error) {
	return s.create(ctx, nil, request)
}

func (s *Service) create(ctx context.Context, p *authz.Principal, request CreateRequest) (Detail, error) {
	if request.RequestID == uuid.Nil {
		return Detail{}, service.Detail(service.ErrInvalidInput, "connector orchestration request ID is required")
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return Detail{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pg(request.AgentID)); err != nil {
		return Detail{}, notFound(err)
	}
	if p != nil {
		if err := authz.Authorize(ctx, q, *p, authz.ConnectorOrchestration, request.AgentID); err != nil {
			return Detail{}, err
		}
	}
	needParams := dbq.GetResourceNeedParams{AgentID: pg(request.AgentID), Type: "connector", Slug: request.NeedSlug}
	discoveredNeed, err := q.GetResourceNeed(ctx, needParams)
	if err != nil {
		return Detail{}, notFound(err)
	}
	requestHash, err := orchestrationRequestHash(request)
	if err != nil {
		return Detail{}, err
	}
	existing, err := q.GetConnectorOrchestrationByRequest(ctx, dbq.GetConnectorOrchestrationByRequestParams{AgentID: pg(request.AgentID), NeedID: discoveredNeed.ID, RequestID: pg(request.RequestID)})
	if err == nil {
		if existing.RequestHash != requestHash {
			return Detail{}, service.Detail(service.ErrConflict, "connector orchestration request ID was already used with different content")
		}
		jobs, listErr := q.ListConnectorJobsByOrchestration(ctx, existing.ID)
		return Detail{Orchestration: existing, Jobs: jobs}, listErr
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Detail{}, err
	}
	if len(request.Input) == 0 || len(request.Input) > 1<<20 || !json.Valid(request.Input) ||
		request.Deadline.Before(time.Now()) || request.Deadline.After(time.Now().Add(24*time.Hour)) {
		return Detail{}, service.Detail(service.ErrInvalidInput, "valid input and a future deadline within 24 hours are required")
	}
	if !validOptions(request) {
		return Detail{}, service.Detail(service.ErrInvalidInput, "invalid connector orchestration options")
	}
	if !discoveredNeed.BoundConnectorGroupID.Valid || (request.GroupID != uuid.Nil && uuid.UUID(discoveredNeed.BoundConnectorGroupID.Bytes) != request.GroupID) {
		return Detail{}, service.Detail(service.ErrConflict, "connector need is not bound to the target group")
	}
	request.GroupID = uuid.UUID(discoveredNeed.BoundConnectorGroupID.Bytes)
	discoveredMembers, err := q.ListConnectorTargetGroupMembers(ctx, pg(request.GroupID))
	if err != nil {
		return Detail{}, err
	}
	connectorIDs := make([]uuid.UUID, len(discoveredMembers))
	for i, member := range discoveredMembers {
		connectorIDs[i] = uuid.UUID(member.ID.Bytes)
	}
	locked, err := connectorssvc.LockResources(ctx, q, connectorIDs)
	if err != nil {
		return Detail{}, notFound(err)
	}
	group, err := q.GetConnectorTargetGroupForUpdate(ctx, pg(request.GroupID))
	if err != nil {
		return Detail{}, notFound(err)
	}
	need, err := q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams(needParams))
	if err != nil {
		return Detail{}, notFound(err)
	}
	if need.ID != discoveredNeed.ID || !need.BoundConnectorGroupID.Valid || uuid.UUID(need.BoundConnectorGroupID.Bytes) != request.GroupID {
		return Detail{}, service.Detail(service.ErrConflict, "connector need binding changed; retry orchestration")
	}
	spec, err := connectorssvc.ParseNeedSpec(need.Spec)
	if err != nil {
		return Detail{}, service.Detail(service.ErrConflict, "%v", err)
	}
	if group.ContractID != spec.ContractID {
		return Detail{}, service.Detail(service.ErrConflict, "connector target group no longer matches the need")
	}
	command, err := connectorssvc.RequiredCommand(spec, request.Command, "job")
	if err != nil {
		return Detail{}, service.Detail(service.ErrForbidden, "%v", err)
	}
	if request.Revision != command.Revision || request.Mode != "job" || request.InputHash != command.InputSchemaHash || request.OutputHash != command.OutputSchemaHash {
		return Detail{}, service.Detail(service.ErrForbidden, "connector orchestration command contract does not exactly match the declared need")
	}
	members, err := q.ListConnectorTargetGroupMembers(ctx, pg(request.GroupID))
	if err != nil {
		return Detail{}, err
	}
	members = filterMembers(members, request.ResourceIDs, request.Labels)
	if len(members) == 0 {
		return Detail{}, service.Detail(service.ErrInvalidInput, "connector target group is empty")
	}
	if request.Quorum > int32(len(members)) {
		return Detail{}, service.Detail(service.ErrInvalidInput, "quorum exceeds target count")
	}
	if request.CanaryCount > int32(len(members)) {
		return Detail{}, service.Detail(service.ErrInvalidInput, "canary count exceeds target count")
	}
	for _, member := range members {
		if _, ok := locked[uuid.UUID(member.ID.Bytes)]; !ok {
			return Detail{}, service.Detail(service.ErrConflict, "connector target group membership changed; retry orchestration")
		}
	}
	if p != nil {
		for _, member := range members {
			if err := authz.AuthorizeResource(ctx, q, *p, authz.ResourceBind, "connector", uuid.UUID(member.ID.Bytes)); err != nil {
				return Detail{}, err
			}
		}
	}
	orchestrationID := uuid.NewSHA1(request.RequestID, []byte(request.AgentID.String()+":"+uuid.UUID(need.ID.Bytes).String()+":orchestration"))
	canaryPhase := "none"
	if request.Strategy == "canary" {
		canaryPhase = "canary"
	}
	parent, err := q.CreateConnectorOrchestration(ctx, dbq.CreateConnectorOrchestrationParams{
		ID: pg(orchestrationID), AgentID: pg(request.AgentID), NeedID: need.ID, RequestID: pg(request.RequestID), TargetGroupID: pg(request.GroupID), InitiatorUserID: initiator(p),
		CommandName: request.Command, CommandRevision: command.Revision, CommandMode: request.Mode,
		InputSchemaHash: command.InputSchemaHash, OutputSchemaHash: command.OutputSchemaHash, InputPayload: request.Input,
		RequestHash: requestHash,
		Strategy:    request.Strategy, OfflinePolicy: request.OfflinePolicy, MaxConcurrency: request.MaxConcurrency,
		BatchSize: request.BatchSize, CanaryCount: request.CanaryCount, CanaryPhase: canaryPhase, Quorum: request.Quorum,
		DeadlineAt: pgtype.Timestamptz{Time: request.Deadline.UTC(), Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Detail{}, service.Detail(service.ErrConflict, "connector orchestration request ID was already used with different content")
	}
	if err != nil {
		return Detail{}, err
	}
	jobs := make([]dbq.ConnectorJob, 0, len(members))
	terminalStatus := ""
	for index, member := range members {
		descriptor, descriptorErr := connectorssvc.ParseDescriptor(member.InterfaceDescriptor)
		compatible := descriptorErr == nil && connectorssvc.Compatible(spec, descriptor) == nil
		ready := member.Readiness == "ready" && compatible
		if !ready && request.OfflinePolicy == "fail" {
			terminalStatus = "failed"
		}
		if !ready && request.OfflinePolicy == "cancel" {
			terminalStatus = "cancelled"
		}
		jobID := uuid.NewSHA1(request.RequestID, []byte(uuid.UUID(member.ID.Bytes).String()+":child"))
		childRequestID := uuid.NewSHA1(request.RequestID, []byte(uuid.UUID(member.ID.Bytes).String()+":request"))
		idempotencyKey := uuid.NewSHA1(request.RequestID, []byte(uuid.UUID(member.ID.Bytes).String()+":execution"))
		canaryCohort := request.Strategy == "canary" && index < int(request.CanaryCount)
		job, err := q.InsertConnectorJob(ctx, dbq.InsertConnectorJobParams{
			ID: pg(jobID), ConnectorID: member.ID, AgentID: pg(request.AgentID), NeedID: need.ID, RequestID: pg(childRequestID),
			OrchestrationID: pg(orchestrationID), TargetPosition: pgtype.Int4{Int32: member.Position, Valid: true},
			CanaryCohort: canaryCohort, OperationKind: "command",
			OperationName: request.Command, OperationRevision: command.Revision, Mode: "job",
			InputSchemaHash: command.InputSchemaHash, OutputSchemaHash: command.OutputSchemaHash,
			InputPayload: request.Input, RequestHash: requestHash, Status: "held", IdempotencyKey: pg(idempotencyKey),
			DeadlineAt: pgtype.Timestamptz{Time: request.Deadline.UTC(), Valid: true},
		})
		if err != nil {
			return Detail{}, err
		}
		if !ready && request.OfflinePolicy == "skip" {
			job, err = q.SkipConnectorJob(ctx, dbq.SkipConnectorJobParams{ID: pg(jobID), ErrorMessage: pgtype.Text{String: "connector offline or incompatible", Valid: true}})
			if err != nil {
				return Detail{}, err
			}
		}
		jobs = append(jobs, job)
	}
	counts := countJobs(jobs)
	decision := Decide(request.Strategy, int(request.MaxConcurrency), int(request.BatchSize), int(request.CanaryCount), int(request.Quorum), counts)
	if terminalStatus != "" {
		decision = Decision{Status: terminalStatus}
	}
	if decision.Release > 0 {
		if _, err := q.ReleaseHeldConnectorJobs(ctx, dbq.ReleaseHeldConnectorJobsParams{OrchestrationID: pg(orchestrationID), Lim: int32(decision.Release), CanaryOnly: request.Strategy == "canary" && canaryPhase == "canary"}); err != nil {
			return Detail{}, err
		}
	}
	if decision.Status != "" {
		if _, err := q.CancelConnectorOrchestrationJobs(ctx, pg(orchestrationID)); err != nil {
			return Detail{}, err
		}
		parent, err = q.SetConnectorOrchestrationStatus(ctx, dbq.SetConnectorOrchestrationStatusParams{ID: pg(orchestrationID), Status: decision.Status})
	} else {
		parent, err = q.StartConnectorOrchestration(ctx, pg(orchestrationID))
	}
	if err != nil {
		return Detail{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Detail{}, err
	}
	if p != nil {
		return s.Get(ctx, *p, uuid.UUID(parent.ID.Bytes))
	}
	return s.loadDetail(ctx, uuid.UUID(parent.ID.Bytes))
}

func (s *Service) Get(ctx context.Context, p authz.Principal, id uuid.UUID) (Detail, error) {
	q := dbq.New(s.db.Pool())
	row, err := q.GetConnectorOrchestration(ctx, pg(id))
	if err != nil {
		return Detail{}, notFound(err)
	}
	if err := authz.Authorize(ctx, q, p, authz.ConnectorJobView, uuid.UUID(row.AgentID.Bytes)); err != nil {
		return Detail{}, err
	}
	jobs, err := q.ListConnectorJobsByOrchestration(ctx, pg(id))
	return Detail{Orchestration: row, Jobs: jobs}, err
}

func orchestrationRequestHash(request CreateRequest) (string, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Service) loadDetail(ctx context.Context, id uuid.UUID) (Detail, error) {
	q := dbq.New(s.db.Pool())
	row, err := q.GetConnectorOrchestrationForUpdate(ctx, pg(id))
	if err != nil {
		return Detail{}, notFound(err)
	}
	jobs, err := q.ListConnectorJobsByOrchestration(ctx, pg(id))
	return Detail{Orchestration: row, Jobs: jobs}, err
}

func (s *Service) GetFromAgent(ctx context.Context, agentID uuid.UUID, needSlug string, id uuid.UUID) (Detail, error) {
	detail, err := s.loadDetail(ctx, id)
	if err != nil {
		return Detail{}, err
	}
	if uuid.UUID(detail.Orchestration.AgentID.Bytes) != agentID {
		return Detail{}, service.ErrNotFound
	}
	need, err := dbq.New(s.db.Pool()).GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: "connector", Slug: needSlug})
	if err != nil || need.ID != detail.Orchestration.NeedID {
		return Detail{}, service.ErrNotFound
	}
	return detail, nil
}

func (s *Service) Advance(ctx context.Context, p authz.Principal, id uuid.UUID) (Detail, error) {
	return s.advance(ctx, &p, id)
}

func (s *Service) AdvanceSystem(ctx context.Context, id uuid.UUID) (Detail, error) {
	return s.advance(ctx, nil, id)
}

func (s *Service) AdvanceConnector(ctx context.Context, connectorID uuid.UUID) error {
	rows, err := dbq.New(s.db.Pool()).ListActiveConnectorOrchestrationsForConnector(ctx, pg(connectorID))
	if err != nil {
		return err
	}
	for _, id := range rows {
		if _, err := s.AdvanceSystem(ctx, uuid.UUID(id.Bytes)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) advance(ctx context.Context, p *authz.Principal, id uuid.UUID) (Detail, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return Detail{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	row, err := q.GetConnectorOrchestrationForUpdate(ctx, pg(id))
	if err != nil {
		return Detail{}, notFound(err)
	}
	if p != nil {
		if err := authz.Authorize(ctx, q, *p, authz.ConnectorOrchestration, uuid.UUID(row.AgentID.Bytes)); err != nil {
			return Detail{}, err
		}
	}
	jobs, err := q.ListConnectorJobsByOrchestration(ctx, pg(id))
	if err != nil {
		return Detail{}, err
	}
	terminalStatus := ""
	if row.CancelRequestedAt.Valid {
		terminalStatus = "cancelled"
	} else if !row.DeadlineAt.Time.After(time.Now()) {
		terminalStatus = "failed"
	} else {
		readiness, readinessErr := q.ListConnectorOrchestrationReadiness(ctx, pg(id))
		if readinessErr != nil {
			return Detail{}, readinessErr
		}
		offline := make([]pgtype.UUID, 0)
		for _, target := range readiness {
			if (!target.Ready.Valid || !target.Ready.Bool) && (target.Status == "held" || target.Status == "queued" || target.Status == "running") {
				offline = append(offline, target.ID)
			}
		}
		if len(offline) > 0 {
			switch row.OfflinePolicy {
			case "fail":
				terminalStatus = "failed"
			case "cancel":
				terminalStatus = "cancelled"
			case "skip":
				_, err = q.ApplyConnectorOrchestrationOfflineSkip(ctx, offline)
			case "wait":
				_, err = q.ApplyConnectorOrchestrationOfflineWait(ctx, offline)
			}
			if err != nil {
				return Detail{}, err
			}
			jobs, err = q.ListConnectorJobsByOrchestration(ctx, pg(id))
			if err != nil {
				return Detail{}, err
			}
		}
	}
	if terminalStatus == "" {
		counts := countJobs(jobs)
		if row.Strategy == "canary" && row.CanaryPhase == "canary" && counts.CanarySucceeded == counts.CanaryTotal {
			row.CanaryPhase = "remainder"
		}
		if row.Strategy == "canary" {
			if err := q.SetConnectorOrchestrationCanaryState(ctx, dbq.SetConnectorOrchestrationCanaryStateParams{ID: pg(id), CanaryPhase: row.CanaryPhase, CanarySucceededCount: int32(counts.CanarySucceeded)}); err != nil {
				return Detail{}, err
			}
		}
		decision := Decide(row.Strategy, int(row.MaxConcurrency), int(row.BatchSize), int(row.CanaryCount), int(row.Quorum), counts)
		if decision.Release > 0 {
			_, err = q.ReleaseHeldConnectorJobs(ctx, dbq.ReleaseHeldConnectorJobsParams{OrchestrationID: pg(id), Lim: int32(decision.Release), CanaryOnly: row.Strategy == "canary" && row.CanaryPhase == "canary"})
		}
		if err == nil {
			terminalStatus = decision.Status
		}
	}
	if err == nil && terminalStatus != "" {
		_, err = q.CancelConnectorOrchestrationJobs(ctx, pg(id))
		if err == nil {
			_, err = q.SetConnectorOrchestrationStatus(ctx, dbq.SetConnectorOrchestrationStatusParams{ID: pg(id), Status: terminalStatus})
		}
	}
	if err != nil {
		return Detail{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Detail{}, err
	}
	if p != nil {
		return s.Get(ctx, *p, id)
	}
	return s.loadDetail(ctx, id)
}

func (s *Service) Cancel(ctx context.Context, p authz.Principal, id uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	row, err := q.GetConnectorOrchestration(ctx, pg(id))
	if err != nil {
		return notFound(err)
	}
	if err := authz.Authorize(ctx, q, p, authz.ConnectorJobCancel, uuid.UUID(row.AgentID.Bytes)); err != nil {
		return err
	}
	if _, err = q.RequestConnectorOrchestrationCancellation(ctx, dbq.RequestConnectorOrchestrationCancellationParams{ID: pg(id), AgentID: row.AgentID}); err != nil {
		return err
	}
	if _, err = q.CancelConnectorOrchestrationJobs(ctx, pg(id)); err != nil {
		return err
	}
	if _, err = q.SetConnectorOrchestrationStatus(ctx, dbq.SetConnectorOrchestrationStatusParams{ID: pg(id), Status: "cancelled"}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) CancelFromAgent(ctx context.Context, agentID uuid.UUID, needSlug string, id uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	row, err := q.GetConnectorOrchestrationForUpdate(ctx, pg(id))
	if err != nil || uuid.UUID(row.AgentID.Bytes) != agentID {
		return service.ErrNotFound
	}
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: "connector", Slug: needSlug})
	if err != nil || need.ID != row.NeedID {
		return service.ErrNotFound
	}
	if _, err = q.RequestConnectorOrchestrationCancellation(ctx, dbq.RequestConnectorOrchestrationCancellationParams{ID: pg(id), AgentID: pg(agentID)}); err != nil {
		return err
	}
	if _, err = q.CancelConnectorOrchestrationJobs(ctx, pg(id)); err != nil {
		return err
	}
	if _, err = q.SetConnectorOrchestrationStatus(ctx, dbq.SetConnectorOrchestrationStatusParams{ID: pg(id), Status: "cancelled"}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func validOptions(request CreateRequest) bool {
	strategy := request.Strategy == "parallel" || request.Strategy == "serial" || request.Strategy == "rolling" || request.Strategy == "canary" || request.Strategy == "quorum"
	offline := request.OfflinePolicy == "fail" || request.OfflinePolicy == "skip" || request.OfflinePolicy == "wait" || request.OfflinePolicy == "cancel"
	return strategy && offline && request.MaxConcurrency > 0 && request.BatchSize > 0 && request.CanaryCount >= 0 && request.Quorum >= 0 &&
		(request.Strategy != "canary" || request.CanaryCount > 0) && (request.Strategy != "quorum" || request.Quorum > 0)
}

func countJobs(jobs []dbq.ConnectorJob) Counts {
	counts := Counts{Total: len(jobs)}
	for _, job := range jobs {
		switch job.Status {
		case "held":
			counts.Held++
		case "queued", "running":
			counts.Active++
		case "succeeded":
			counts.Succeeded++
		case "failed", "cancelled":
			counts.Failed++
		case "skipped":
			counts.Skipped++
		}
		if job.CanaryCohort {
			counts.CanaryTotal++
			switch job.Status {
			case "queued", "running":
				counts.CanaryActive++
			case "succeeded":
				counts.CanarySucceeded++
				counts.CanaryTerminal++
			case "failed", "cancelled", "skipped":
				counts.CanaryFailed++
				counts.CanaryTerminal++
			}
		}
	}
	return counts
}

func reservationConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func initiator(p *authz.Principal) pgtype.UUID {
	if p == nil {
		return pgtype.UUID{}
	}
	return pg(p.UserID)
}

func filterMembers(members []dbq.ListConnectorTargetGroupMembersRow, resourceIDs []uuid.UUID, labels map[string]string) []dbq.ListConnectorTargetGroupMembersRow {
	if len(resourceIDs) == 0 && len(labels) == 0 {
		return members
	}
	wanted := make(map[uuid.UUID]struct{}, len(resourceIDs))
	for _, id := range resourceIDs {
		wanted[id] = struct{}{}
	}
	out := make([]dbq.ListConnectorTargetGroupMembersRow, 0, len(members))
	for _, member := range members {
		if len(wanted) > 0 {
			if _, ok := wanted[uuid.UUID(member.ID.Bytes)]; !ok {
				continue
			}
		}
		var memberLabels map[string]string
		if len(labels) > 0 && json.Unmarshal(member.Labels, &memberLabels) != nil {
			continue
		}
		matches := true
		for key, value := range labels {
			if memberLabels[key] != value {
				matches = false
				break
			}
		}
		if matches {
			out = append(out, member)
		}
	}
	return out
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return service.ErrNotFound
	}
	return err
}
