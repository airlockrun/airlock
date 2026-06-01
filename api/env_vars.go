package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/go-chi/chi/v5"
)

// Operator-side env-var endpoints. The agent-internal counterparts
// (UpsertEnvVar / GetEnvVarValue, mounted under /api/agent) live in
// agentapi/env_vars.go.

// ListEnvVars handles GET /api/v1/agents/{agentID}/env-vars (operator).
func (h *credentialHandler) ListEnvVars(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agentID")
		return
	}
	p := principalFromRequest(r)
	rows, err := h.svc.ListEnvVars(r.Context(), p, agentID)
	if err != nil {
		writeConnError(w, err, "failed to list env vars")
		return
	}
	out := make([]*airlockv1.EnvVarInfo, 0, len(rows))
	for _, ev := range rows {
		out = append(out, convert.EnvVarToProto(ev))
	}
	writeProto(w, http.StatusOK, &airlockv1.ListEnvVarsResponse{EnvVars: out})
}

// setEnvVarValueRequest is the body for POST /api/v1/agents/{agentID}/env-vars/{slug}.
type setEnvVarValueRequest struct {
	Value string `json:"value"`
}

// SetEnvVarValue handles POST /api/v1/agents/{agentID}/env-vars/{slug} (operator).
func (h *credentialHandler) SetEnvVarValue(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req setEnvVarValueRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.SetEnvVarValue(r.Context(), p, agentID, slug, req.Value); err != nil {
		writeConnError(w, err, "failed to store value")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ClearEnvVarValue handles DELETE /api/v1/agents/{agentID}/env-vars/{slug} (operator).
func (h *credentialHandler) ClearEnvVarValue(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.ClearEnvVarValue(r.Context(), p, agentID, slug); err != nil {
		writeConnError(w, err, "failed to clear value")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetupStatus handles GET /api/v1/agents/{agentID}/setup-status.
func (h *credentialHandler) SetupStatus(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agentID")
		return
	}
	p := principalFromRequest(r)
	c, err := h.svc.SetupStatus(r.Context(), p, agentID)
	if err != nil {
		writeConnError(w, err, "failed to load setup status")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.ConnectionSetupStatusResponse{
		Counts: convert.SetupCountsToProto(c),
	})
}
