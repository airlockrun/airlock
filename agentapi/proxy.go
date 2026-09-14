package agentapi

import (
	"io"
	"net/http"

	"github.com/airlockrun/agentsdk/wire"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

func (h *Handler) ServiceProxy(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	var req wire.ProxyRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.appService().ServiceProxy(r.Context(), slug, req)
	if err != nil {
		h.appError(w, err)
		return
	}
	defer resp.Body.Close()

	// Copy upstream response headers and status.
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Cap the proxied response at MaxBufferedResponseBytes — same ceiling
	// the agent SDK applies to conn.Request. Defense in depth: without
	// this, a runaway upstream can OOM the agent process (which does
	// io.ReadAll on its end). The +1 sentinel detects overflow so we can
	// log loudly; the early close lets the agent's reader surface a
	// short-read as a clean "upstream truncated" error.
	written, err := io.Copy(w, io.LimitReader(resp.Body, int64(runtimesvc.MaxBufferedResponseBytes)+1))
	if err != nil {
		h.logger.Warn("connection proxy stream copy",
			zap.String("slug", slug),
			zap.Int64("bytes_written", written),
			zap.Error(err))
		return
	}
	if written > int64(runtimesvc.MaxBufferedResponseBytes) {
		h.logger.Warn("connection proxy hit hard cap",
			zap.String("slug", slug),
			zap.Int64("max_bytes", int64(runtimesvc.MaxBufferedResponseBytes)))
	}
}
