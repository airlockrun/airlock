package api

import (
	"net/http"

	"github.com/airlockrun/sol/webfetch"
	"go.uber.org/zap"
)

// WebFetch handles POST /api/agent/webfetch — proxies URL fetching
// for agent containers. Currently a pass-through; future: logging,
// URL allowlists, rate limiting.
func (h *agentHandler) WebFetch(w http.ResponseWriter, r *http.Request) {
	var req webfetch.Request
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.URL == "" {
		writeJSONError(w, http.StatusBadRequest, "url is required")
		return
	}

	client := webfetch.NewClient()
	resp, err := client.Fetch(r.Context(), req)
	if err != nil {
		h.logger.Error("webfetch failed", zap.String("url", req.URL), zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "fetch failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
