package agentapi

import (
	"context"
	"net/http"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/oauth"
	"github.com/go-chi/chi/v5"
)

func (h *Handler) MCPToolCall(w http.ResponseWriter, r *http.Request) {
	var req wire.MCPToolCallRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().MCPToolCall(r.Context(), chi.URLParam(r, "slug"), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// DiscoverMCPAuth runs RFC 9728/8414 discovery on an MCP server URL.
func DiscoverMCPAuth(ctx context.Context, httpClient *http.Client, serverURL string) (*oauth.DiscoveryResult, error) {
	return oauth.DiscoverUpstream(ctx, httpClient, serverURL)
}
