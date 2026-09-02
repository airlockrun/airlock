package api

import (
	"net/http"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	connectorartifactssvc "github.com/airlockrun/airlock/service/connectorartifacts"
	"github.com/go-chi/chi/v5"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type connectorArtifactsHandler struct {
	service *connectorartifactssvc.Service
}

const (
	connectorArtifactsListRoute    = "/agents/{agentID}/needs/connector/{slug}/artifacts"
	connectorArtifactDownloadRoute = "/agents/{agentID}/needs/connector/{slug}/artifacts/{artifactFileID}/download"
)

func newConnectorArtifactsHandler(service *connectorartifactssvc.Service) *connectorArtifactsHandler {
	if service == nil {
		panic("api: connector artifact service is required")
	}
	return &connectorArtifactsHandler{service: service}
}

func (h *connectorArtifactsHandler) List(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	sets, err := h.service.List(r.Context(), principalFromRequest(r), agentID, chi.URLParam(r, "slug"))
	if err != nil {
		writeServiceError(w, err, "failed to list connector artifacts")
		return
	}
	writeProto(w, http.StatusOK, connectorArtifactSetsToProto(sets))
}

func connectorArtifactSetsToProto(sets []connectorartifactssvc.ArtifactSet) *airlockv1.ListConnectorArtifactsResponse {
	out := make([]*airlockv1.ConnectorArtifactSetInfo, len(sets))
	for i, set := range sets {
		files := make([]*airlockv1.ConnectorArtifactFileInfo, len(set.Files))
		for j, file := range set.Files {
			files[j] = &airlockv1.ConnectorArtifactFileInfo{
				Id: file.ID.String(), Platform: file.Platform, Filename: file.Filename,
				Sha256: file.Digest, SizeBytes: file.SizeBytes, NoticesSha256: file.NoticesDigest,
				NoticesSizeBytes: file.NoticesSizeBytes,
			}
		}
		out[i] = &airlockv1.ConnectorArtifactSetInfo{
			Id: set.ID.String(), BuildId: set.BuildID.String(), ConnectorSlug: set.ConnectorSlug,
			SourceRef: set.SourceRef, Kind: set.Kind, ContractId: set.ContractID, Name: set.Name,
			Description: set.Description, ArtifactVersion: set.ArtifactVersion,
			ProtocolMajor: set.ProtocolMajor, ProtocolMinor: set.ProtocolMinor, Features: set.Features,
			ServiceMode:   set.ServiceMode,
			InterfaceJson: string(set.InterfaceDescriptor), InterfaceHash: set.InterfaceHash,
			SettingsJson: string(set.SettingsSchema), Files: files,
			CreatedAt: timestamppb.New(set.CreatedAt), ArtifactDigest: set.ArtifactDigest,
		}
	}
	response := &airlockv1.ListConnectorArtifactsResponse{ArtifactSets: out}
	if len(sets) > 0 {
		response.ConnectorSlug = sets[0].ConnectorSlug
		response.Name = sets[0].Name
		response.Description = sets[0].Description
	}
	return response
}

func (h *connectorArtifactsHandler) Download(w http.ResponseWriter, r *http.Request) {
	agentID, agentErr := parseUUID(chi.URLParam(r, "agentID"))
	fileID, fileErr := parseUUID(chi.URLParam(r, "artifactFileID"))
	if agentErr != nil || fileErr != nil {
		writeError(w, http.StatusBadRequest, "invalid agent or artifact file ID")
		return
	}
	request := &airlockv1.DownloadConnectorArtifactRequest{}
	if err := decodeProto(r, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	download, err := h.service.DownloadURL(r.Context(), principalFromRequest(r), agentID, chi.URLParam(r, "slug"), fileID, request.Notices)
	if err != nil {
		writeServiceError(w, err, "failed to authorize connector artifact download")
		return
	}
	writeProto(w, http.StatusOK, connectorArtifactDownloadToProto(download))
}

func connectorArtifactDownloadToProto(download connectorartifactssvc.Download) *airlockv1.DownloadConnectorArtifactResponse {
	return &airlockv1.DownloadConnectorArtifactResponse{
		Url: download.URL, DownloadUrl: download.URL, Filename: download.Filename, Sha256: download.Digest,
		SizeBytes: download.SizeBytes, ExpiresAt: timestamppb.New(download.ExpiresAt),
	}
}
