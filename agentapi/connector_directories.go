package agentapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (h *Handler) ConnectorDirectoryList(w http.ResponseWriter, r *http.Request) {
	limit, ok := directoryIntQuery(w, r, "limit")
	if !ok {
		return
	}
	result, err := h.connectorDirectories.List(r.Context(), auth.AgentIDFromContext(r.Context()), chi.URLParam(r, "needSlug"), chi.URLParam(r, "directory"), protocol.DirectoryListRequest{
		Path: r.URL.Query().Get("path"), Cursor: r.URL.Query().Get("cursor"), Limit: limit,
	})
	writeDirectoryResult(w, result, err)
}

func (h *Handler) ConnectorDirectoryStat(w http.ResponseWriter, r *http.Request) {
	result, err := h.connectorDirectories.Stat(r.Context(), auth.AgentIDFromContext(r.Context()), chi.URLParam(r, "needSlug"), chi.URLParam(r, "directory"), r.URL.Query().Get("path"))
	writeDirectoryResult(w, result, err)
}

func (h *Handler) ConnectorDirectoryRead(w http.ResponseWriter, r *http.Request) {
	offset, ok := directoryInt64Query(w, r, "offset")
	if !ok {
		return
	}
	length, ok := directoryInt64Query(w, r, "length")
	if !ok {
		return
	}
	result, err := h.connectorDirectories.Read(r.Context(), auth.AgentIDFromContext(r.Context()), chi.URLParam(r, "needSlug"), chi.URLParam(r, "directory"), protocol.DirectoryReadRequest{
		Path: r.URL.Query().Get("path"), Offset: offset, Length: length,
	})
	writeDirectoryResult(w, result, err)
}

func (h *Handler) ConnectorDirectoryWrite(w http.ResponseWriter, r *http.Request) {
	var request protocol.DirectoryWriteRequest
	if !readDirectoryBody(w, r, &request) {
		return
	}
	result, err := h.connectorDirectories.Write(r.Context(), auth.AgentIDFromContext(r.Context()), chi.URLParam(r, "needSlug"), chi.URLParam(r, "directory"), request)
	writeDirectoryResult(w, result, err)
}

func (h *Handler) ConnectorDirectoryDelete(w http.ResponseWriter, r *http.Request) {
	var request map[string]json.RawMessage
	if !readDirectoryBody(w, r, &request) {
		return
	}
	var filePath string
	if len(request) != 1 || json.Unmarshal(request["path"], &filePath) != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.connectorDirectories.Delete(r.Context(), auth.AgentIDFromContext(r.Context()), chi.URLParam(r, "needSlug"), chi.URLParam(r, "directory"), filePath); err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ConnectorDirectoryMove(w http.ResponseWriter, r *http.Request) {
	var request protocol.DirectoryMoveRequest
	if !readDirectoryBody(w, r, &request) {
		return
	}
	if err := h.connectorDirectories.Move(r.Context(), auth.AgentIDFromContext(r.Context()), chi.URLParam(r, "needSlug"), chi.URLParam(r, "directory"), request); err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ConnectorDirectoryImport(w http.ResponseWriter, r *http.Request) {
	var request agentsdk.ConnectorImportRequest
	if !readDirectoryBody(w, r, &request) {
		return
	}
	runID, ok := connectorRunID(w, r)
	if !ok {
		return
	}
	result, err := h.connectorDirectories.Import(r.Context(), auth.AgentIDFromContext(r.Context()), runID, chi.URLParam(r, "needSlug"), chi.URLParam(r, "directory"), request)
	writeDirectoryResult(w, result, err)
}

func (h *Handler) ConnectorDirectoryExport(w http.ResponseWriter, r *http.Request) {
	var request agentsdk.ConnectorExportRequest
	if !readDirectoryBody(w, r, &request) {
		return
	}
	runID, ok := connectorRunID(w, r)
	if !ok {
		return
	}
	result, err := h.connectorDirectories.Export(r.Context(), auth.AgentIDFromContext(r.Context()), runID, chi.URLParam(r, "needSlug"), chi.URLParam(r, "directory"), request)
	writeDirectoryResult(w, result, err)
}

func readDirectoryBody(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, protocol.MaxEnvelopeBytes)
	if err := readJSON(r, destination); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func connectorRunID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.Header.Get("X-Airlock-Run-ID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "valid X-Airlock-Run-ID is required for storage transfer")
		return uuid.Nil, false
	}
	return id, true
}

func directoryIntQuery(w http.ResponseWriter, r *http.Request, name string) (int, bool) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return 0, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid "+name)
		return 0, false
	}
	return parsed, true
}

func directoryInt64Query(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	value := r.URL.Query().Get(name)
	if value == "" {
		return 0, true
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid "+name)
		return 0, false
	}
	return parsed, true
}

func writeDirectoryResult(w http.ResponseWriter, result any, err error) {
	if err != nil {
		writeConnectorServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
