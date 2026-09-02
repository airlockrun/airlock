package api

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	connectororchestrationsvc "github.com/airlockrun/airlock/service/connectororchestration"
	connectorssvc "github.com/airlockrun/airlock/service/connectors"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type connectorsHandler struct {
	connectors    *connectorssvc.Service
	orchestration *connectororchestrationsvc.Service
}

func newConnectorsHandler(connectors *connectorssvc.Service, orchestration *connectororchestrationsvc.Service) *connectorsHandler {
	if connectors == nil || orchestration == nil {
		panic("api: connector services are required")
	}
	return &connectorsHandler{connectors: connectors, orchestration: orchestration}
}

func (h *connectorsHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.connectors.List(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to list connectors")
		return
	}
	out := make([]*airlockv1.ConnectorInfo, len(rows))
	for i, row := range rows {
		out[i] = connectorToProto(row)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListConnectorsResponse{Connectors: out})
}

func (h *connectorsHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "connectorID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid connector ID")
		return
	}
	row, err := h.connectors.Get(r.Context(), principalFromRequest(r), id)
	if err != nil {
		writeServiceError(w, err, "failed to get connector")
		return
	}
	writeProto(w, http.StatusOK, connectorDetailToProto(row))
}

func (h *connectorsHandler) SetLabels(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "connectorID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid connector ID")
		return
	}
	request := &airlockv1.SetConnectorLabelsRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	_, err = h.connectors.SetLabels(r.Context(), principalFromRequest(r), id, request.Labels)
	if err != nil {
		writeServiceError(w, err, "failed to set connector labels")
		return
	}
	row, err := h.connectors.Get(r.Context(), principalFromRequest(r), id)
	if err != nil {
		writeServiceError(w, err, "failed to reload connector")
		return
	}
	writeProto(w, http.StatusOK, connectorDetailToProto(row))
}

func (h *connectorsHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := h.orchestration.ListGroups(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to list connector target groups")
		return
	}
	out := make([]*airlockv1.ConnectorTargetGroupInfo, len(rows))
	for i, row := range rows {
		out[i] = groupToProto(row)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListConnectorTargetGroupsResponse{Groups: out})
}

func (h *connectorsHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	request := &airlockv1.CreateConnectorTargetGroupRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agentID, err := uuid.Parse(request.AgentId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	connectorIDs := make([]uuid.UUID, len(request.ConnectorIds))
	for i, value := range request.ConnectorIds {
		connectorIDs[i], err = uuid.Parse(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid connector ID")
			return
		}
	}
	row, err := h.orchestration.CreateGroup(r.Context(), principalFromRequest(r), connectororchestrationsvc.CreateGroupRequest{
		AgentID: agentID, NeedSlug: request.NeedSlug, Name: request.Name,
		Description: request.Description, ConnectorIDs: connectorIDs,
	})
	if err != nil {
		writeServiceError(w, err, "failed to create connector target group")
		return
	}
	writeProto(w, http.StatusCreated, groupToProto(row))
}

func (h *connectorsHandler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID, err := parseUUID(chi.URLParam(r, "groupID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target group ID")
		return
	}
	request := &airlockv1.AddConnectorTargetGroupMemberRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	connectorID, err := uuid.Parse(request.ConnectorId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid connector ID")
		return
	}
	if err := h.orchestration.AddGroupMember(r.Context(), principalFromRequest(r), groupID, connectorID, request.Position); err != nil {
		writeServiceError(w, err, "failed to add connector target group member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *connectorsHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	groupID, err := parseUUID(chi.URLParam(r, "groupID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid target group ID")
		return
	}
	connectorID, err := parseUUID(chi.URLParam(r, "connectorID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid connector ID")
		return
	}
	if err := h.orchestration.RemoveGroupMember(r.Context(), principalFromRequest(r), groupID, connectorID); err != nil {
		writeServiceError(w, err, "failed to remove connector target group member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *connectorsHandler) CreateOrchestration(w http.ResponseWriter, r *http.Request) {
	request := &airlockv1.CreateConnectorOrchestrationRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agentID, agentErr := uuid.Parse(request.AgentId)
	groupID, groupErr := uuid.Parse(request.TargetGroupId)
	requestID, requestErr := uuid.Parse(request.RequestId)
	if agentErr != nil || groupErr != nil || requestErr != nil || request.DeadlineAt == nil || !request.DeadlineAt.IsValid() {
		writeError(w, http.StatusBadRequest, "invalid orchestration target or deadline")
		return
	}
	detail, err := h.orchestration.Create(r.Context(), principalFromRequest(r), connectororchestrationsvc.CreateRequest{
		AgentID: agentID, NeedSlug: request.NeedSlug, RequestID: requestID, GroupID: groupID, Command: request.Command,
		Input: json.RawMessage(request.InputJson), Strategy: request.Strategy, OfflinePolicy: request.OfflinePolicy,
		MaxConcurrency: request.MaxConcurrency, BatchSize: request.BatchSize, CanaryCount: request.CanaryCount,
		Quorum: request.Quorum, Deadline: request.DeadlineAt.AsTime(), Revision: request.CommandRevision,
		Mode: request.CommandMode, InputHash: request.InputSchemaHash, OutputHash: request.OutputSchemaHash,
	})
	if err != nil {
		writeServiceError(w, err, "failed to create connector orchestration")
		return
	}
	writeProto(w, http.StatusCreated, orchestrationToProto(detail))
}

func (h *connectorsHandler) GetOrchestration(w http.ResponseWriter, r *http.Request) {
	h.orchestrationByID(w, r, false)
}

func (h *connectorsHandler) AdvanceOrchestration(w http.ResponseWriter, r *http.Request) {
	h.orchestrationByID(w, r, true)
}

func (h *connectorsHandler) orchestrationByID(w http.ResponseWriter, r *http.Request, advance bool) {
	id, err := parseUUID(chi.URLParam(r, "orchestrationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid orchestration ID")
		return
	}
	var detail connectororchestrationsvc.Detail
	if advance {
		detail, err = h.orchestration.Advance(r.Context(), principalFromRequest(r), id)
	} else {
		detail, err = h.orchestration.Get(r.Context(), principalFromRequest(r), id)
	}
	if err != nil {
		writeServiceError(w, err, "failed to get connector orchestration")
		return
	}
	writeProto(w, http.StatusOK, orchestrationToProto(detail))
}

func (h *connectorsHandler) CancelOrchestration(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "orchestrationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid orchestration ID")
		return
	}
	if err := h.orchestration.Cancel(r.Context(), principalFromRequest(r), id); err != nil {
		writeServiceError(w, err, "failed to cancel connector orchestration")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func connectorToProto(resource connectorssvc.Resource) *airlockv1.ConnectorInfo {
	row := resource.Row
	canView := slices.Contains(resource.Capabilities, "view")
	canManage := slices.Contains(resource.Capabilities, "manage")
	info := &airlockv1.ConnectorInfo{
		Id: uuid.UUID(row.ID.Bytes).String(), Slug: row.Slug, DisplayName: row.DisplayName,
		ContractId: row.ContractID.String, Readiness: row.Readiness, Lifecycle: row.Lifecycle,
		AgentCount: resource.AgentCount, Capabilities: resource.Capabilities,
		Online: row.Lifecycle == "active" && row.Readiness != "offline",
	}
	if canManage {
		info.OwnerPrincipalId = uuid.UUID(row.OwnerPrincipalID.Bytes).String()
		info.OwnerName, info.OwnerKind = resource.OwnerName, resource.OwnerKind
	}
	if !canView {
		return info
	}
	labels := map[string]string{}
	_ = json.Unmarshal(row.Labels, &labels)
	commands := make([]*airlockv1.ConnectorPublishedCommandInfo, len(resource.Commands))
	for i, command := range resource.Commands {
		commands[i] = &airlockv1.ConnectorPublishedCommandInfo{
			Name: command.Name, Revision: command.Revision, Description: command.Description, Mode: command.Mode,
			InputSchemaHash: command.InputSchemaHash, OutputSchemaHash: command.OutputSchemaHash,
			InputSchemaJson: string(command.InputSchema), OutputSchemaJson: string(command.OutputSchema),
		}
	}
	directories := make([]*airlockv1.ConnectorPublishedDirectoryInfo, len(resource.Directories))
	for i, directory := range resource.Directories {
		directories[i] = &airlockv1.ConnectorPublishedDirectoryInfo{
			Name: directory.Name, Revision: directory.Revision, Description: directory.Description,
			Read: directory.Read, Write: directory.Write, List: directory.List,
		}
	}
	return &airlockv1.ConnectorInfo{
		Id: uuid.UUID(row.ID.Bytes).String(), OwnerPrincipalId: uuid.UUID(row.OwnerPrincipalID.Bytes).String(), Slug: row.Slug,
		Kind: row.Kind.String, ContractId: row.ContractID.String, Name: row.Name.String, DisplayName: row.DisplayName,
		Description: row.Description.String, ProtocolMajor: row.ProtocolMajor.Int32, ProtocolMinor: row.ProtocolMinor.Int32,
		Features: row.Features, ArtifactVersion: row.ArtifactVersion.String, ArtifactDigest: row.ArtifactDigest.String,
		InterfaceJson: string(row.InterfaceDescriptor), InterfaceHash: row.InterfaceHash.String, Readiness: row.Readiness,
		ReadinessMessage: row.ReadinessMessage.String, Labels: labels, Lifecycle: row.Lifecycle, AgentCount: resource.AgentCount,
		Capabilities: resource.Capabilities, LastSeenAt: convert.PgTimestampToProto(row.LastSeenAt), LastReadyAt: convert.PgTimestampToProto(row.LastReadyAt),
		CreatedAt: convert.PgTimestampToProto(row.CreatedAt), UpdatedAt: convert.PgTimestampToProto(row.UpdatedAt),
		OwnerName: resource.OwnerName, OwnerKind: resource.OwnerKind, Online: row.Lifecycle == "active" && row.Readiness != "offline",
		Commands: commands, Directories: directories, ArtifactFreshness: resource.ArtifactStatus.Freshness,
		UpdateStatus: resource.ArtifactStatus.UpdateStatus, LatestArtifactVersion: resource.ArtifactStatus.LatestVersion,
		LatestArtifactDigest: resource.ArtifactStatus.LatestDigest, LatestInterfaceHash: resource.ArtifactStatus.LatestInterfaceHash,
		LatestArtifactCreatedAt: convert.PgTimestampToProto(resource.ArtifactStatus.LatestArtifactCreated),
		ActiveProvenance:        row.ActiveProvenance, RollbackProvenance: row.RollbackProvenance,
		ActiveObservationState: row.ActiveObservationState, RollbackObservationState: row.RollbackObservationState,
		InventoryRevision: uint64(row.InventoryRevision), ObservedActiveDigest: row.ObservedActiveDigest.String,
		ObservedActiveManifestJson: string(row.ObservedActiveManifest), ObservedActiveManifestHash: row.ObservedActiveManifestHash.String,
		ObservedRollbackDigest: row.ObservedRollbackDigest.String, ObservedRollbackManifestJson: string(row.ObservedRollbackManifest),
		ObservedRollbackManifestHash: row.ObservedRollbackManifestHash.String,
	}
}

func connectorDetailToProto(resource connectorssvc.Resource) *airlockv1.GetConnectorResponse {
	grants := make([]*airlockv1.ConnectorResourceGrantInfo, len(resource.Grants))
	for i, grant := range resource.Grants {
		grants[i] = &airlockv1.ConnectorResourceGrantInfo{
			Id: grant.ID.String(), GranteeId: grant.GranteeID.String(), GranteeName: grant.GranteeName,
			GranteeKind: grant.GranteeKind, Capabilities: grant.Capabilities,
		}
	}
	consumers := make([]*airlockv1.ResourceConsumerInfo, len(resource.Consumers))
	for i, consumer := range resource.Consumers {
		consumers[i] = &airlockv1.ResourceConsumerInfo{
			AgentId: consumer.AgentID.String(), AgentName: consumer.AgentName, AgentSlug: consumer.AgentSlug,
			NeedType: consumer.NeedType, NeedSlug: consumer.NeedSlug, CanAccessAgent: consumer.CanAccessAgent,
		}
		if consumer.CanAccessAgent {
			consumers[i].AgentDetailPath = "/agents/" + consumer.AgentSlug
		}
	}
	return &airlockv1.GetConnectorResponse{Connector: connectorToProto(resource), Grants: grants, Consumers: consumers}
}

func groupToProto(group connectororchestrationsvc.Group) *airlockv1.ConnectorTargetGroupInfo {
	result := connectorTargetGroupToProto(group.Row, group.MemberCount, group.ReadyMemberCount)
	result.Capabilities = group.Capabilities
	return result
}

func connectorTargetGroupToProto(row dbq.ConnectorTargetGroup, memberCount, readyMemberCount int32) *airlockv1.ConnectorTargetGroupInfo {
	return &airlockv1.ConnectorTargetGroupInfo{
		Id: uuid.UUID(row.ID.Bytes).String(), OwnerPrincipalId: uuid.UUID(row.OwnerPrincipalID.Bytes).String(),
		Name: row.Name, Description: row.Description, ContractId: row.ContractID,
		CreatedAt: convert.PgTimestampToProto(row.CreatedAt), UpdatedAt: convert.PgTimestampToProto(row.UpdatedAt),
		MemberCount: memberCount, ReadyMemberCount: readyMemberCount,
	}
}

func orchestrationToProto(detail connectororchestrationsvc.Detail) *airlockv1.ConnectorOrchestrationResponse {
	row := detail.Orchestration
	orchestration := &airlockv1.ConnectorOrchestrationInfo{
		Id: uuid.UUID(row.ID.Bytes).String(), AgentId: uuid.UUID(row.AgentID.Bytes).String(), NeedId: uuid.UUID(row.NeedID.Bytes).String(),
		RequestId: uuid.UUID(row.RequestID.Bytes).String(), TargetGroupId: uuid.UUID(row.TargetGroupID.Bytes).String(), CommandName: row.CommandName, CommandRevision: row.CommandRevision,
		CommandMode: row.CommandMode, InputSchemaHash: row.InputSchemaHash, OutputSchemaHash: row.OutputSchemaHash,
		Strategy: row.Strategy, OfflinePolicy: row.OfflinePolicy, MaxConcurrency: row.MaxConcurrency, BatchSize: row.BatchSize,
		CanaryCount: row.CanaryCount, CanaryPhase: row.CanaryPhase, CanarySucceededCount: row.CanarySucceededCount, Quorum: row.Quorum, Status: row.Status,
		CancelRequestedAt: convert.PgTimestampToProto(row.CancelRequestedAt), DeadlineAt: convert.PgTimestampToProto(row.DeadlineAt),
		StartedAt: convert.PgTimestampToProto(row.StartedAt), CompletedAt: convert.PgTimestampToProto(row.CompletedAt),
		CreatedAt: convert.PgTimestampToProto(row.CreatedAt), UpdatedAt: convert.PgTimestampToProto(row.UpdatedAt),
	}
	jobs := make([]*airlockv1.ConnectorJobInfo, len(detail.Jobs))
	for i, job := range detail.Jobs {
		jobs[i] = &airlockv1.ConnectorJobInfo{
			Id: uuid.UUID(job.ID.Bytes).String(), ConnectorId: uuid.UUID(job.ConnectorID.Bytes).String(), AgentId: uuid.UUID(job.AgentID.Bytes).String(),
			NeedId: uuid.UUID(job.NeedID.Bytes).String(), RequestId: uuid.UUID(job.RequestID.Bytes).String(), OrchestrationId: uuid.UUID(job.OrchestrationID.Bytes).String(), TargetPosition: job.TargetPosition.Int32,
			OperationName: job.OperationName, OperationRevision: job.OperationRevision, Mode: job.Mode, Status: job.Status,
			InputSchemaHash: job.InputSchemaHash, OutputSchemaHash: job.OutputSchemaHash, CanaryCohort: job.CanaryCohort,
			InputJson: string(job.InputPayload), OutputJson: string(job.OutputPayload), ErrorCode: job.ErrorCode.String, ErrorMessage: job.ErrorMessage.String,
			CancelRequestedAt: convert.PgTimestampToProto(job.CancelRequestedAt), DeadlineAt: convert.PgTimestampToProto(job.DeadlineAt),
			StartedAt: convert.PgTimestampToProto(job.StartedAt), CompletedAt: convert.PgTimestampToProto(job.CompletedAt),
			CreatedAt: convert.PgTimestampToProto(job.CreatedAt), UpdatedAt: convert.PgTimestampToProto(job.UpdatedAt),
		}
	}
	return &airlockv1.ConnectorOrchestrationResponse{Orchestration: orchestration, Jobs: jobs}
}
