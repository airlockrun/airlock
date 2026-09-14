package agentapi

import (
	"net/http"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"go.uber.org/zap"
)

// Search handles POST /api/agent/search — proxies web search requests
// from agent containers without exposing API keys.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	var req wire.SearchProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Query == "" {
		writeJSONError(w, http.StatusBadRequest, "query is required")
		return
	}

	agentID := auth.AgentIDFromContext(r.Context())

	client, err := runtimesvc.ResolveSearchClient(r.Context(), h.db, h.encryptor, h.logger, agentID.String(), req.Slug)
	if err != nil {
		h.logger.Warn("search not available", zap.String("agent", agentID.String()), zap.Error(err))
		writeJSONError(w, http.StatusNotFound, "web search not configured")
		return
	}

	resp, err := client.Search(r.Context(), req.Request)
	if err != nil {
		h.logger.Error("web search failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "search failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
