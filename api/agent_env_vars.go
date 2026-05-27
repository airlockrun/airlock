package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// --- agent-side (agent JWT) env var endpoints — unchanged, stay in api ---

// agentEnvVarValueResponse is the body returned to an agent fetching one env var.
type agentEnvVarValueResponse struct {
	Value string `json:"value"`
}

// envVarRef is the canonical secrets.Store path for an env var value.
// Mirrored from the service package so the agent-internal upsert path
// (UpsertEnvVar / GetEnvVarValue) keeps writing to the same ref shape.
func envVarRef(id, slug string) string { return "agent/env-var/" + id + "/" + slug }

// envVarUpsertRequest mirrors agentsdk.EnvVarDef. We don't import the SDK
// type here because the SDK is consumed by the agent (build dependency);
// the API server only sees the wire shape.
type envVarUpsertRequest struct {
	Slug         string `json:"slug"`
	Description  string `json:"description,omitempty"`
	IsSecret     bool   `json:"isSecret"`
	DefaultValue string `json:"defaultValue,omitempty"`
	Pattern      string `json:"pattern,omitempty"`
}

// UpsertEnvVar handles PUT /api/agent/env-vars/{slug}. The agent declares
// its required env vars at sync time; we upsert the registration row
// (slot definition, no value yet).
func (h *agentHandler) UpsertEnvVar(w http.ResponseWriter, r *http.Request) {
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
		Slug:         req.Slug,
		Description:  req.Description,
		IsSecret:     req.IsSecret,
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
func (h *agentHandler) GetEnvVarValue(w http.ResponseWriter, r *http.Request) {
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

// --- operator (user JWT) env var endpoints — now thin wrappers around connections.Service ---

// envVarInfo is the wire shape ListEnvVars returns.
type envVarInfo struct {
	Slug         string     `json:"slug"`
	Description  string     `json:"description,omitempty"`
	IsSecret     bool       `json:"isSecret"`
	Configured   bool       `json:"configured"`
	DefaultValue string     `json:"defaultValue,omitempty"`
	Pattern      string     `json:"pattern,omitempty"`
	Value        string     `json:"value,omitempty"`
	UpdatedAt    *time.Time `json:"updatedAt,omitempty"`
}

// ListEnvVars handles GET /api/v1/agents/{agentID}/env-vars (operator).
func (h *credentialHandler) ListEnvVars(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agentID")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	rows, err := h.svc.ListEnvVars(r.Context(), userID, agentID)
	if err != nil {
		writeConnError(w, err, "failed to list env vars")
		return
	}
	out := make([]envVarInfo, 0, len(rows))
	for _, ev := range rows {
		info := envVarInfo{
			Slug: ev.Slug, Description: ev.Description, IsSecret: ev.IsSecret,
			Configured: ev.Configured, Pattern: ev.Pattern,
			DefaultValue: ev.DefaultValue, Value: ev.Value,
		}
		t := ev.UpdatedAt
		info.UpdatedAt = &t
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, map[string]any{"envVars": out})
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
	userID := auth.UserIDFromContext(r.Context())
	if err := h.svc.SetEnvVarValue(r.Context(), userID, agentID, slug, req.Value); err != nil {
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
	userID := auth.UserIDFromContext(r.Context())
	if err := h.svc.ClearEnvVarValue(r.Context(), userID, agentID, slug); err != nil {
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
	userID := auth.UserIDFromContext(r.Context())
	c, err := h.svc.SetupStatus(r.Context(), userID, agentID)
	if err != nil {
		writeConnError(w, err, "failed to load setup status")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"connections": c.Connections,
		"mcpServers":  c.MCPServers,
		"envVars":     c.EnvVars,
		"total":       c.Connections + c.MCPServers + c.EnvVars,
	})
}

// suppress unused-import warning for secrets when the agent-side
// endpoints temporarily change shape during refactors.
var _ secrets.Store
var _ context.Context
var _ pgtype.UUID
var _ json.RawMessage
