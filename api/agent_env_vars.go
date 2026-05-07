// Env var endpoints for both agent-internal sync and operator UI.
// Agent-internal handlers live on agentHandler (same as MCP/connection
// upserts); operator-facing handlers live on credentialHandler (same
// shape as the rest of the credential surface).
package api

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// UpsertEnvVar handles PUT /api/agent/env-vars/{slug}. Called from the
// agent's syncWithAirlock. Declares (or updates) a slot; the value is
// set separately by an operator via SetEnvVarValue.
func (h *agentHandler) UpsertEnvVar(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeJSONError(w, http.StatusBadRequest, "slug is required")
		return
	}

	var def agentsdk.EnvVarDef
	if err := readJSON(r, &def); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Defense in depth — the agentsdk panics on this combination, but
	// the wire could still carry it from a non-canonical client.
	if def.Secret && def.Default != "" {
		writeJSONError(w, http.StatusBadRequest, "secret env vars cannot have a default value")
		return
	}

	if def.Pattern != "" {
		if _, err := regexp.Compile(def.Pattern); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid pattern: "+err.Error())
			return
		}
	}

	q := dbq.New(h.db.Pool())

	// If the agent's redeclared pattern differs from what we have on
	// file AND a value is stored, validate the stored value against the
	// new pattern. On mismatch, clear value_ref so the operator sees
	// "needs setup" rather than a configured slot whose value the
	// runtime would reject. Only fires on actual pattern changes — no
	// extra decrypt per sync in steady state.
	existing, err := q.GetAgentEnvVarBySlug(r.Context(), dbq.GetAgentEnvVarBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err == nil && existing.Pattern != def.Pattern && existing.ValueRef != "" && def.Pattern != "" {
		current, derr := h.encryptor.Get(r.Context(), envVarRef(pgUUID(existing.ID).String(), slug), existing.ValueRef)
		if derr != nil {
			h.logger.Warn("env var pattern-change validation: decrypt failed",
				zap.String("slug", slug), zap.Error(derr))
		} else if !regexp.MustCompile(def.Pattern).MatchString(current) {
			if cerr := q.ClearAgentEnvVarValue(r.Context(), dbq.ClearAgentEnvVarValueParams{
				AgentID: toPgUUID(agentID),
				Slug:    slug,
			}); cerr != nil {
				h.logger.Error("env var pattern-change clear failed",
					zap.String("slug", slug), zap.Error(cerr))
			} else {
				h.logger.Info("env var cleared: stored value no longer matches updated pattern",
					zap.String("slug", slug))
			}
		}
	}

	if _, err := q.UpsertAgentEnvVar(r.Context(), dbq.UpsertAgentEnvVarParams{
		AgentID:      toPgUUID(agentID),
		Slug:         slug,
		Description:  def.Description,
		IsSecret:     def.Secret,
		DefaultValue: def.Default,
		Pattern:      def.Pattern,
	}); err != nil {
		h.logger.Error("upsert env var failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to register env var")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetEnvVarValue handles GET /api/agent/env-vars/{slug}. Returns the
// decrypted value for runtime use. Falls through to the agent-declared
// default when the operator hasn't configured the slot yet (only valid
// for non-secret slots — secret slots without a value return 404 so the
// agent code surfaces a clear error).
func (h *agentHandler) GetEnvVarValue(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")

	q := dbq.New(h.db.Pool())
	row, err := q.GetAgentEnvVarBySlug(r.Context(), dbq.GetAgentEnvVarBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "env var not registered")
			return
		}
		h.logger.Error("get env var failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load env var")
		return
	}

	if row.ValueRef == "" {
		// Operator hasn't set a value. Fall through to the
		// agent-declared default (always "" for secrets, by the
		// RegisterEnvVar invariant). Empty string is a legitimate
		// return — agent code that requires non-empty should declare a
		// Pattern that rejects "" at save time.
		writeJSON(w, http.StatusOK, map[string]string{"value": row.DefaultValue})
		return
	}

	value, err := h.encryptor.Get(r.Context(), envVarRef(pgUUID(row.ID).String(),slug), row.ValueRef)
	if err != nil {
		h.logger.Error("decrypt env var failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"value": value})
}

// envVarInfo is the operator-facing list shape. Value is included only
// for non-secret rows; secret rows get an empty string regardless of
// whether they're configured (the operator can't read secrets back from
// the UI — only rotate).
type envVarInfo struct {
	Slug         string     `json:"slug"`
	Description  string     `json:"description"`
	IsSecret     bool       `json:"isSecret"`
	Configured   bool       `json:"configured"`
	DefaultValue string     `json:"defaultValue,omitempty"`
	Pattern      string     `json:"pattern,omitempty"`
	Value        string     `json:"value,omitempty"`
	UpdatedAt    *time.Time `json:"updatedAt,omitempty"`
}

// ListEnvVars handles GET /api/v1/agents/{agentID}/env-vars (operator).
func (h *credentialHandler) ListEnvVars(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agentID")
		return
	}
	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	rows, err := q.ListAgentEnvVars(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list env vars failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list env vars")
		return
	}

	out := make([]envVarInfo, 0, len(rows))
	for _, row := range rows {
		info := envVarInfo{
			Slug:        row.Slug,
			Description: row.Description,
			IsSecret:    row.IsSecret,
			Configured:  row.Configured,
			Pattern:     row.Pattern,
		}
		if !row.IsSecret {
			info.DefaultValue = row.DefaultValue
		}
		if row.Configured && !row.IsSecret {
			// Decrypt and surface the current value for plain config so
			// operators can see+edit. Secrets stay write-only.
			value, derr := h.encryptor.Get(ctx, envVarRef(pgUUID(row.ID).String(),row.Slug), envVarValueRef(ctx, q, agentID, row.Slug))
			if derr != nil {
				h.logger.Error("decrypt env var for list failed",
					zap.String("slug", row.Slug), zap.Error(derr))
			} else {
				info.Value = value
			}
		}
		t := row.UpdatedAt.Time
		info.UpdatedAt = &t
		out = append(out, info)
	}

	writeJSON(w, http.StatusOK, map[string]any{"envVars": out})
}

// envVarValueRef re-fetches the row to get the value_ref. ListAgentEnvVars
// drops it intentionally so the operator-list flow doesn't accidentally
// surface the encrypted blob; for plain config we re-fetch the single
// row to feed encryptor.Get. Cheap relative to the decrypt cost.
func envVarValueRef(ctx context.Context, q *dbq.Queries, agentID [16]byte, slug string) string {
	row, err := q.GetAgentEnvVarBySlug(ctx, dbq.GetAgentEnvVarBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		return ""
	}
	return row.ValueRef
}

// SetEnvVarValueRequest is the body for POST /api/v1/agents/{agentID}/env-vars/{slug}.
type SetEnvVarValueRequest struct {
	Value string `json:"value"`
}

// SetEnvVarValue handles POST /api/v1/agents/{agentID}/env-vars/{slug}
// (operator). Encrypts and stores the value.
func (h *credentialHandler) SetEnvVarValue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, slug, err := h.resolveEnvVarSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	var req SetEnvVarValueRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	q := dbq.New(h.db.Pool())
	row, err := q.GetAgentEnvVarBySlug(ctx, dbq.GetAgentEnvVarBySlugParams{
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

	if row.Pattern != "" {
		// Pattern was validated at registration time, so Compile here
		// is defensive — surfaces a 500 if somehow stored invalid
		// rather than silently accepting any value.
		re, perr := regexp.Compile(row.Pattern)
		if perr != nil {
			h.logger.Error("env var pattern invalid in DB", zap.String("slug", slug), zap.Error(perr))
			writeError(w, http.StatusInternalServerError, "stored pattern is invalid")
			return
		}
		if !re.MatchString(req.Value) {
			writeError(w, http.StatusBadRequest, "value does not match required pattern")
			return
		}
	}

	encRef, err := h.encryptor.Put(ctx, envVarRef(pgUUID(row.ID).String(), slug), req.Value)
	if err != nil {
		h.logger.Error("encrypt env var failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	if err := q.SetAgentEnvVarValue(ctx, dbq.SetAgentEnvVarValueParams{
		AgentID:  toPgUUID(agentID),
		Slug:     slug,
		ValueRef: encRef,
	}); err != nil {
		h.logger.Error("store env var value failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to store value")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ClearEnvVarValue handles DELETE /api/v1/agents/{agentID}/env-vars/{slug}
// (operator). Clears the configured value; the slot itself stays
// (re-declared on the next agent sync).
func (h *credentialHandler) ClearEnvVarValue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, slug, err := h.resolveEnvVarSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	if err := q.ClearAgentEnvVarValue(ctx, dbq.ClearAgentEnvVarValueParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	}); err != nil {
		h.logger.Error("clear env var failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to clear value")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetupStatus handles GET /api/v1/agents/{agentID}/setup-status. Returns
// counts of registered connections / MCP servers / env vars that need
// operator action before the agent can run cleanly. Used by
// AgentDetailView to surface a "Needs setup" tag next to the run state.
func (h *credentialHandler) SetupStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agentID")
		return
	}
	if err := h.verifyAgentOwner(ctx, agentID, r); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	q := dbq.New(h.db.Pool())
	row, err := q.AgentSetupStatus(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("setup status failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load setup status")
		return
	}

	total := row.Connections + row.McpServers + row.EnvVars
	writeJSON(w, http.StatusOK, map[string]any{
		"connections": row.Connections,
		"mcpServers":  row.McpServers,
		"envVars":     row.EnvVars,
		"total":       total,
	})
}

// envVarRef is the canonical secrets.Store path for an env var value.
// Stable per (id, slug) so rotations encrypt against the same ref —
// same shape as connection/MCP refs (path-style; Vault-ready).
func envVarRef(id, slug string) string {
	return "agent/env-var/" + id + "/" + slug
}

func (h *credentialHandler) resolveEnvVarSlug(r *http.Request) (agentID [16]byte, slug string, err error) {
	id, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		return id, "", fmt.Errorf("invalid agentID")
	}
	slug = chi.URLParam(r, "slug")
	if slug == "" {
		return id, "", fmt.Errorf("slug is required")
	}
	return id, slug, nil
}
