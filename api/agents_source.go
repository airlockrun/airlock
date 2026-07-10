package api

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/airlockrun/airlock/authz"
	agentssvc "github.com/airlockrun/airlock/service/agents"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const sourceUploadMaxCompressedBytes = 50 << 20 // 50 MiB

// SourceState handles HEAD /api/v1/agents/{agentID}/source.
func (h *agentsHandler) SourceState(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	state, err := h.svc.SourceState(r.Context(), principalFromRequest(r), agentID)
	if err != nil {
		writeAgentsError(w, err, "failed to inspect source")
		return
	}
	if state == "" {
		writeError(w, http.StatusConflict, "agent has no source yet")
		return
	}
	w.Header().Set("ETag", strconv.Quote(state))
	w.WriteHeader(http.StatusOK)
}

// DownloadSource handles GET /api/v1/agents/{agentID}/source.
func (h *agentsHandler) DownloadSource(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	tmp, err := os.CreateTemp("", "airlock-source-download-*.tar.gz")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to prepare source download")
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	state, err := h.svc.DownloadSource(r.Context(), principalFromRequest(r), agentID, tmp)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		writeAgentsError(w, err, "failed to download source")
		return
	}
	tmp, err = os.Open(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open source download")
		return
	}
	defer tmp.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("ETag", strconv.Quote(state))
	if _, err := io.Copy(w, tmp); err != nil {
		return
	}
}

// UploadSource handles PUT /api/v1/agents/{agentID}/source.
func (h *agentsHandler) UploadSource(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "application/gzip" && ct != "application/x-gzip" {
		writeError(w, http.StatusUnsupportedMediaType, "source upload must use Content-Type application/gzip")
		return
	}
	p := principalFromRequest(r)
	body := http.MaxBytesReader(w, r.Body, sourceUploadMaxCompressedBytes)
	defer body.Close()
	expectedState := strings.TrimSpace(r.Header.Get("If-Match"))
	if expectedState != "" {
		if unquoted, err := strconv.Unquote(expectedState); err == nil {
			expectedState = unquoted
		}
	}
	force := strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Airlock-Force")), "true")
	state, err := h.svc.UploadSource(r.Context(), p, agentID, body, expectedState, force)
	if errors.Is(err, agentssvc.ErrSourcePreconditionRequired) {
		h.setSourceGitHeaders(w, r, p, agentID)
		writeError(w, http.StatusPreconditionRequired, "source state is required; pull or clone the current source before deploying")
		return
	}
	if errors.Is(err, agentssvc.ErrSourceStateMismatch) {
		h.setSourceGitHeaders(w, r, p, agentID)
		writeError(w, http.StatusPreconditionFailed, "source changed since this workspace last synced")
		return
	}
	if err != nil {
		writeAgentsError(w, err, "failed to upload source")
		return
	}
	w.Header().Set("ETag", strconv.Quote(state))
	w.WriteHeader(http.StatusAccepted)
}

func (h *agentsHandler) setSourceGitHeaders(w http.ResponseWriter, r *http.Request, p authz.Principal, agentID uuid.UUID) {
	if cfg, err := h.svc.GetGitConfig(r.Context(), p, agentID); err == nil && cfg.RemoteURL != "" {
		w.Header().Set("X-Airlock-Git-Remote", cfg.RemoteURL)
		w.Header().Set("X-Airlock-Git-Branch", cfg.DefaultBranch)
		w.Header().Set("X-Airlock-Git-Mode", cfg.Mode)
	}
}
