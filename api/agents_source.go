package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

const sourceUploadMaxCompressedBytes = 50 << 20 // 50 MiB

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
	if err := h.svc.UploadSource(r.Context(), p, agentID, body); err != nil {
		writeAgentsError(w, err, "failed to upload source")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
