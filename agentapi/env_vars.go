package agentapi

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// agentEnvVarValueResponse is the body returned to an agent fetching one env var.
type agentEnvVarValueResponse struct {
	Value string `json:"value"`
}

// envVarRef is the canonical secrets.Store path for an env var value.
// Mirrored from the service package so the agent-internal upsert path
// (UpsertEnvVar / GetEnvVarValue) keeps writing to the same ref shape.
func envVarRef(id, slug string) string { return "agent/env-var/" + id + "/" + slug }

// envVarUpsertRequest is the body agentsdk sends for
// PUT /api/agent/env-vars/{slug}. JSON tags match agentsdk.EnvVarDef's wire
// shape exactly (secret, default). The slug is authoritative from the URL —
// not the body — mirroring the exec-endpoint and connection handlers.
type envVarUpsertRequest struct {
	Description  string `json:"description,omitempty"`
	Secret       bool   `json:"secret"`
	DefaultValue string `json:"default,omitempty"`
	Pattern      string `json:"pattern,omitempty"`
}

// UpsertEnvVar handles PUT /api/agent/env-vars/{slug}. The agent declares
// its required env vars at sync time; we upsert the registration row
// (slot definition, no value yet).
func (h *Handler) UpsertEnvVar(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "slug is required")
		return
	}
	var req envVarUpsertRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Pattern != "" {
		if _, err := regexp.Compile(req.Pattern); err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid pattern: %s", err.Error()))
			return
		}
	}
	q := dbq.New(h.db.Pool())
	if _, err := q.UpsertAgentEnvVar(r.Context(), dbq.UpsertAgentEnvVarParams{
		AgentID:      toPgUUID(agentID),
		Slug:         slug,
		Description:  req.Description,
		IsSecret:     req.Secret,
		DefaultValue: req.DefaultValue,
		Pattern:      req.Pattern,
	}); err != nil {
		h.logger.Error("upsert env var failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to register env var")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetEnvVarValue handles GET /api/agent/env-vars/{slug} — runtime read
// of a configured value. Returns 404 if the slot exists but has no
// configured value (so the agent can fall back to default or fail
// loudly per its own policy).
func (h *Handler) GetEnvVarValue(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "slug is required")
		return
	}
	q := dbq.New(h.db.Pool())
	row, err := q.GetAgentEnvVarBySlug(r.Context(), dbq.GetAgentEnvVarBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "env var not registered")
			return
		}
		h.logger.Error("get env var failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load env var")
		return
	}
	if row.ValueRef == "" {
		writeError(w, http.StatusNotFound, "env var has no configured value")
		return
	}
	value, err := h.encryptor.Get(r.Context(), envVarRef(uuid.UUID(row.ID.Bytes).String(), slug), row.ValueRef)
	if err != nil {
		h.logger.Error("decrypt env var failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	writeJSON(w, http.StatusOK, agentEnvVarValueResponse{Value: value})
}
