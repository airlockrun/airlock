package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

var proxyHTTPClient = &http.Client{Timeout: 30 * time.Second}

// ServiceProxy handles POST /api/agent/proxy/{slug}.
func (h *agentHandler) ServiceProxy(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")

	var req agentsdk.ProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	q := dbq.New(h.db.Pool())
	conn, err := q.GetConnectionBySlug(r.Context(), dbq.GetConnectionBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "connection not found")
			return
		}
		h.logger.Error("get connection failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to get connection")
		return
	}

	// No credentials → 402 auth required.
	if conn.Credentials == "" {
		writeJSON(w, http.StatusPaymentRequired, map[string]string{
			"error":    "auth_required",
			"slug":     conn.Slug,
			"connName": conn.Name,
			"authUrl":  buildCredentialAuthURL(h.publicURL, agentID, slug, conn.AuthMode),
			"message":  fmt.Sprintf("%s needs authorization", conn.Name),
		})
		return
	}

	// Token expired → 402, refresh job should have caught this.
	if conn.TokenExpiresAt.Valid && conn.TokenExpiresAt.Time.Before(time.Now()) {
		writeJSON(w, http.StatusPaymentRequired, map[string]string{
			"error":    "auth_required",
			"slug":     conn.Slug,
			"connName": conn.Name,
			"authUrl":  buildCredentialAuthURL(h.publicURL, agentID, slug, conn.AuthMode),
			"message":  fmt.Sprintf("%s authorization has expired", conn.Name),
		})
		return
	}

	// Decrypt credentials.
	creds, err := h.encryptor.Decrypt(conn.Credentials)
	if err != nil {
		h.logger.Error("decrypt credentials failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to decrypt credentials")
		return
	}

	// Build upstream request.
	url := conn.BaseUrl + req.Path
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}

	upstream, err := http.NewRequestWithContext(r.Context(), method, url, bodyReader)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid upstream request: %v", err))
		return
	}
	if req.Body != "" {
		upstream.Header.Set("Content-Type", "application/json")
	}

	// Inject auth.
	injectAuth(upstream, conn.AuthInjection, creds)

	resp, err := proxyHTTPClient.Do(upstream)
	if err != nil {
		h.logger.Error("proxy upstream request failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "upstream request failed")
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
	io.Copy(w, resp.Body)
}

// injectAuth adds credentials to the upstream request based on the auth injection config.
func injectAuth(req *http.Request, authInjectionJSON []byte, creds string) {
	var injection agentsdk.AuthInjection
	if err := json.Unmarshal(authInjectionJSON, &injection); err != nil {
		return
	}

	switch injection.Type {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+creds)
	case "api_key_header":
		name := injection.Name
		if name == "" {
			name = "X-API-Key"
		}
		req.Header.Set(name, creds)
	case "bot_token_url_prefix":
		req.URL.Path = "/" + creds + req.URL.Path
	}
}

// buildCredentialAuthURL returns an Airlock-hosted URL for users to authorize a connection.
func buildCredentialAuthURL(publicURL string, agentID uuid.UUID, slug, authMode string) string {
	switch authMode {
	case "oauth":
		return fmt.Sprintf("%s/api/v1/credentials/oauth/start?agent_id=%s&slug=%s",
			publicURL, agentID, slug)
	case "token":
		return fmt.Sprintf("%s/ui/credentials/new?agent_id=%s&slug=%s",
			publicURL, agentID, slug)
	default:
		return ""
	}
}
