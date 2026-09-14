package api

import (
	"net/http"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/agents"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func agentAccessHandler(svc *agents.Service, update bool) http.HandlerFunc {
	if svc == nil {
		panic("api: agents service is required")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(chi.URLParam(r, "agentID"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid agent ID")
			return
		}
		p := principalFromRequest(r)
		var settings agents.AccessSettings
		if update {
			var req airlockv1.AgentAccessSettings
			if err := decodeProto(r, &req); err != nil {
				writeError(w, http.StatusBadRequest, "invalid body")
				return
			}
			settings, err = svc.UpdateAccessSettings(r.Context(), p, id, agents.AccessSettings{McpEnabled: req.McpEnabled, AllowPublicMcp: req.AllowPublicMcp, AllowPublicRoutes: req.AllowPublicRoutes})
		} else {
			settings, err = svc.GetAccessSettings(r.Context(), p, id)
		}
		if err != nil {
			writeError(w, service.HTTPStatus(err), "access settings unavailable")
			return
		}
		writeProto(w, http.StatusOK, &airlockv1.AgentAccessSettings{McpEnabled: settings.McpEnabled, AllowPublicMcp: settings.AllowPublicMcp, AllowPublicRoutes: settings.AllowPublicRoutes})
	}
}
