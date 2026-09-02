package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	hostssvc "github.com/airlockrun/airlock/service/hosts"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type hostsHandler struct {
	hosts *hostssvc.Service
}

func newHostsHandler(hosts *hostssvc.Service) *hostsHandler {
	if hosts == nil {
		panic("api: host service is required")
	}
	return &hostsHandler{hosts: hosts}
}

func (h *hostsHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.hosts.List(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to list hosts")
		return
	}
	out := make([]*airlockv1.HostInfo, len(rows))
	for i, row := range rows {
		out[i] = &airlockv1.HostInfo{
			Id: uuid.UUID(row.ID.Bytes).String(), Name: row.Name, Platform: row.Platform,
			Architecture: row.Architecture, AccessMode: row.AccessMode, Version: row.Version,
			ProtocolVersion: row.ProtocolVersion, Lifecycle: row.Lifecycle,
			LastSeenAt: convert.PgTimestampToProto(row.LastSeenAt), CreatedAt: convert.PgTimestampToProto(row.CreatedAt), UpdatedAt: convert.PgTimestampToProto(row.UpdatedAt),
			ConnectorCount: row.ConnectorCount, ActiveJobCount: row.ActiveJobCount,
			OwnerUserId: uuid.UUID(row.OwnerPrincipalID.Bytes).String(), Capabilities: row.Capabilities,
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListHostsResponse{Hosts: out})
}

func (h *hostsHandler) Get(w http.ResponseWriter, r *http.Request) {
	hostID, err := parseUUID(chi.URLParam(r, "hostID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid host ID")
		return
	}
	detail, err := h.hosts.Get(r.Context(), principalFromRequest(r), hostID)
	if err != nil {
		writeServiceError(w, err, "failed to get host")
		return
	}
	connectors := make([]*airlockv1.ConnectorInfo, len(detail.Connectors))
	for i, row := range detail.Connectors {
		connectors[i] = hostedConnectorToProto(row)
	}
	jobs := make([]*airlockv1.HostManagementJobInfo, len(detail.Jobs))
	for i, row := range detail.Jobs {
		jobs[i] = hostJobToProto(row, false)
	}
	host := hostToProto(detail.Host, int32(len(connectors)), activeHostJobs(detail.Jobs))
	host.OwnerName, host.Capabilities = detail.OwnerName, detail.Capabilities
	writeProto(w, http.StatusOK, &airlockv1.GetHostResponse{Host: host, Connectors: connectors, ManagementJobs: jobs})
}

func activeHostJobs(jobs []dbq.HostManagementJob) int32 {
	var count int32
	for _, job := range jobs {
		if job.Status == "queued" || job.Status == "running" {
			count++
		}
	}
	return count
}

func hostToProto(row dbq.Host, connectorCount, activeJobs int32) *airlockv1.HostInfo {
	return &airlockv1.HostInfo{
		Id: uuid.UUID(row.ID.Bytes).String(), Name: row.Name, Platform: row.Platform,
		Architecture: row.Architecture, AccessMode: row.AccessMode, Version: row.Version,
		ProtocolVersion: row.ProtocolVersion, Lifecycle: row.Lifecycle,
		LastSeenAt: convert.PgTimestampToProto(row.LastSeenAt), CreatedAt: convert.PgTimestampToProto(row.CreatedAt), UpdatedAt: convert.PgTimestampToProto(row.UpdatedAt),
		ConnectorCount: connectorCount, ActiveJobCount: activeJobs,
		OwnerUserId: uuid.UUID(row.OwnerPrincipalID.Bytes).String(),
	}
}

func hostedConnectorToProto(row dbq.ConnectorResource) *airlockv1.ConnectorInfo {
	return &airlockv1.ConnectorInfo{
		Id: uuid.UUID(row.ID.Bytes).String(), HostId: uuid.UUID(row.HostID.Bytes).String(),
		OwnerPrincipalId: uuid.UUID(row.OwnerPrincipalID.Bytes).String(), Slug: row.Slug,
		Kind: row.Kind.String, ContractId: row.ContractID.String, Name: row.Name.String,
		DisplayName: row.DisplayName, Description: row.Description.String,
		ProtocolMajor: row.ProtocolMajor.Int32, ProtocolMinor: row.ProtocolMinor.Int32,
		Features: row.Features, ArtifactVersion: row.ArtifactVersion.String, ArtifactDigest: row.ArtifactDigest.String,
		InterfaceJson: string(row.InterfaceDescriptor), InterfaceHash: row.InterfaceHash.String,
		Readiness: row.Readiness, ReadinessMessage: row.ReadinessMessage.String, Lifecycle: row.Lifecycle,
		ActiveProvenance: row.ActiveProvenance, RollbackProvenance: row.RollbackProvenance,
		ActiveObservationState: row.ActiveObservationState, RollbackObservationState: row.RollbackObservationState,
		InventoryRevision: uint64(row.InventoryRevision), ObservedActiveDigest: row.ObservedActiveDigest.String,
		ObservedActiveManifestJson: string(row.ObservedActiveManifest), ObservedActiveManifestHash: row.ObservedActiveManifestHash.String,
		ObservedRollbackDigest: row.ObservedRollbackDigest.String, ObservedRollbackManifestJson: string(row.ObservedRollbackManifest),
		ObservedRollbackManifestHash: row.ObservedRollbackManifestHash.String,
		Online:                       row.Lifecycle == "active" && row.Readiness != "offline",
		LastSeenAt:                   convert.PgTimestampToProto(row.LastSeenAt), LastReadyAt: convert.PgTimestampToProto(row.LastReadyAt),
		CreatedAt: convert.PgTimestampToProto(row.CreatedAt), UpdatedAt: convert.PgTimestampToProto(row.UpdatedAt),
	}
}

func (h *hostsHandler) InspectEnrollment(w http.ResponseWriter, r *http.Request) {
	request := &airlockv1.InspectHostEnrollmentRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	row, err := h.hosts.InspectEnrollment(r.Context(), principalFromRequest(r), request.UserCode)
	if err != nil {
		writeServiceError(w, err, "failed to inspect host enrollment")
		return
	}
	writeProto(w, http.StatusOK, hostEnrollmentToProto(row))
}

func hostEnrollmentToProto(row dbq.HostEnrollmentSession) *airlockv1.HostEnrollmentInfo {
	var info protocol.HostInfo
	_ = json.Unmarshal(row.HostInfo, &info)
	status := row.Status
	if row.ExpiresAt.Valid && !row.ExpiresAt.Time.After(time.Now()) && status == "pending" {
		status = "expired"
	}
	return &airlockv1.HostEnrollmentInfo{
		Status: status, UserCode: row.UserCodeDisplay, Name: info.Name, Platform: info.Platform,
		Architecture: info.Architecture, AccessMode: string(info.AccessMode), Version: info.Version,
		ProtocolVersion: int32(info.ProtocolVersion), ExpiresAt: convert.PgTimestampToProto(row.ExpiresAt),
	}
}

func (h *hostsHandler) ApproveEnrollment(w http.ResponseWriter, r *http.Request) {
	request := &airlockv1.ApproveHostEnrollmentRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	row, err := h.hosts.ApproveEnrollment(r.Context(), principalFromRequest(r), request.UserCode)
	if err != nil {
		writeServiceError(w, err, "failed to approve host enrollment")
		return
	}
	writeProto(w, http.StatusOK, hostEnrollmentToProto(row))
}

func (h *hostsHandler) DenyEnrollment(w http.ResponseWriter, r *http.Request) {
	request := &airlockv1.DenyHostEnrollmentRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.hosts.DenyEnrollment(r.Context(), principalFromRequest(r), request.UserCode); err != nil {
		writeServiceError(w, err, "failed to deny host enrollment")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *hostsHandler) Shell(w http.ResponseWriter, r *http.Request) {
	hostID, err := parseUUID(chi.URLParam(r, "hostID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid host ID")
		return
	}
	request := &airlockv1.RequestHostShellRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	job, err := h.hosts.RequestShell(r.Context(), principalFromRequest(r), hostID, protocol.ShellInput{
		Command: request.Command, Arguments: request.Arguments, Environment: request.Environment, WorkingDirectory: request.WorkingDirectory, Stdin: request.Stdin,
	}, time.Duration(request.TimeoutSeconds)*time.Second)
	if err != nil {
		writeServiceError(w, err, "failed to request host shell")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.HostManagementJobResponse{Job: hostJobToProto(job, false)})
}

func (h *hostsHandler) Install(w http.ResponseWriter, r *http.Request) {
	hostID, err := parseUUID(chi.URLParam(r, "hostID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid host ID")
		return
	}
	request := &airlockv1.RequestConnectorInstallRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agentID, agentErr := uuid.Parse(request.AgentId)
	artifactID, artifactErr := uuid.Parse(request.ArtifactFileId)
	if agentErr != nil || artifactErr != nil {
		writeError(w, http.StatusBadRequest, "invalid agent or artifact file ID")
		return
	}
	job, err := h.hosts.RequestInstall(r.Context(), principalFromRequest(r), hostID, hostssvc.InstallRequest{
		AgentID: agentID, NeedSlug: request.NeedSlug, ArtifactFileID: artifactID,
		DisplayName: request.DisplayName, Settings: json.RawMessage(request.SettingsJson), Timeout: time.Duration(request.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		writeServiceError(w, err, "failed to request connector install")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.HostManagementJobResponse{Job: hostJobToProto(job, false)})
}

func (h *hostsHandler) UpdateConnector(w http.ResponseWriter, r *http.Request) {
	connectorID, err := parseUUID(chi.URLParam(r, "connectorID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid connector ID")
		return
	}
	request := &airlockv1.RequestConnectorUpdateRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	artifactID, err := uuid.Parse(request.ArtifactFileId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid artifact file ID")
		return
	}
	job, err := h.hosts.RequestUpdate(r.Context(), principalFromRequest(r), connectorID, artifactID, json.RawMessage(request.SettingsJson), time.Duration(request.TimeoutSeconds)*time.Second)
	if err != nil {
		writeServiceError(w, err, "failed to request connector update")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.HostManagementJobResponse{Job: hostJobToProto(job, false)})
}

func (h *hostsHandler) RemoveConnector(w http.ResponseWriter, r *http.Request) {
	connectorID, err := parseUUID(chi.URLParam(r, "connectorID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid connector ID")
		return
	}
	request := &airlockv1.RequestConnectorRemoveRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	job, err := h.hosts.RequestRemove(r.Context(), principalFromRequest(r), connectorID, time.Duration(request.TimeoutSeconds)*time.Second)
	if err != nil {
		writeServiceError(w, err, "failed to request connector removal")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.HostManagementJobResponse{Job: hostJobToProto(job, false)})
}

func (h *hostsHandler) RollbackConnector(w http.ResponseWriter, r *http.Request) {
	connectorID, err := parseUUID(chi.URLParam(r, "connectorID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid connector ID")
		return
	}
	request := &airlockv1.RequestConnectorRollbackRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	job, err := h.hosts.RequestRollback(r.Context(), principalFromRequest(r), connectorID, time.Duration(request.TimeoutSeconds)*time.Second)
	if err != nil {
		writeServiceError(w, err, "failed to request connector rollback")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.HostManagementJobResponse{Job: hostJobToProto(job, false)})
}

func (h *hostsHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := parseUUID(chi.URLParam(r, "jobID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid management job ID")
		return
	}
	job, events, err := h.hosts.GetJob(r.Context(), principalFromRequest(r), jobID)
	if err != nil {
		writeServiceError(w, err, "failed to get management job")
		return
	}
	out := make([]*airlockv1.HostManagementEventInfo, len(events))
	for i, event := range events {
		out[i] = &airlockv1.HostManagementEventInfo{
			Sequence: event.Sequence, AttemptSequence: event.AttemptSequence, Phase: event.Phase,
			Message: event.Message, EventTime: convert.PgTimestampToProto(event.EventTime), CreatedAt: convert.PgTimestampToProto(event.CreatedAt),
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.GetHostManagementJobResponse{Job: hostJobToProto(job, true), Events: out})
}

func hostJobToProto(row dbq.HostManagementJob, includePayloads bool) *airlockv1.HostManagementJobInfo {
	connectorID, artifactFileID, requestedBy := "", "", ""
	if row.ConnectorID.Valid {
		connectorID = uuid.UUID(row.ConnectorID.Bytes).String()
	}
	if row.ArtifactFileID.Valid {
		artifactFileID = uuid.UUID(row.ArtifactFileID.Bytes).String()
	}
	if row.RequestedByUserID.Valid {
		requestedBy = uuid.UUID(row.RequestedByUserID.Bytes).String()
	}
	result := &airlockv1.HostManagementJobInfo{
		Id: uuid.UUID(row.ID.Bytes).String(), HostId: uuid.UUID(row.HostID.Bytes).String(), ConnectorId: connectorID,
		RequestedByUserId: requestedBy, Kind: row.Kind,
		ArtifactFileId: artifactFileID, Status: row.Status, ErrorMessage: row.ErrorMessage.String,
		DeadlineAt: convert.PgTimestampToProto(row.DeadlineAt), StartedAt: convert.PgTimestampToProto(row.StartedAt),
		CompletedAt: convert.PgTimestampToProto(row.CompletedAt), CreatedAt: convert.PgTimestampToProto(row.CreatedAt), UpdatedAt: convert.PgTimestampToProto(row.UpdatedAt),
	}
	if includePayloads && row.Kind != "connector_install" && row.Kind != "connector_update" {
		result.InputJson, result.OutputJson = string(row.InputPayload), string(row.OutputPayload)
	}
	return result
}
