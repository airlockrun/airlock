package agentapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/sol/webfetch"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

var proxyHTTPClient = newPublicHTTPClient(30 * time.Second)

// ServiceProxy handles POST /api/agent/proxy/{slug}.
func (h *Handler) ServiceProxy(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")

	var req agentsdk.ProxyRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	q := dbq.New(h.db.Pool())
	// Resolve the agent's connection need to its bound resource. The proxy and
	// the credential refresh below key on the resolved resource's own id, so
	// one connection can back many agents' bindings.
	conn, err := q.ResolveBoundConnection(r.Context(), dbq.ResolveBoundConnectionParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "connection not bound")
			return
		}
		h.logger.Error("resolve connection failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to get connection")
		return
	}

	// auth_mode='none' connections proxy without credentials — no token
	// lookup, no decrypt, no injection. Public APIs (MediaWiki, etc.)
	// declared with ConnectionAuthNone land here.
	noAuth := conn.AuthMode == string(agentsdk.ConnectionAuthNone)

	// Resolve credentials (skipped for auth_mode='none'). EnsureConnectionToken
	// renews an expired access token on demand, under a row lock, so a lapsed
	// token self-heals on this very call instead of waiting for the background
	// refresh tick. Only a genuinely unrecoverable connection (no token / no
	// refresh token / provider-revoked) returns 402 auth_required; the agent's
	// system prompt already routes the user to the settings page, so the body
	// carries only slug/connName, not a raw OAuth URL.
	var creds string
	if !noAuth {
		token, err := oauth.EnsureConnectionToken(r.Context(), h.db, h.encryptor, h.oauthClient, h.logger, conn.ID, time.Now())
		switch {
		case errors.Is(err, oauth.ErrNeedsReauth):
			writeJSON(w, http.StatusPaymentRequired, map[string]string{
				"error":    "auth_required",
				"slug":     conn.Slug,
				"connName": conn.Name,
				"message":  fmt.Sprintf("%s needs authorization", conn.Name),
			})
			return
		case err != nil:
			// Transient refresh/decrypt failure — the connection may recover,
			// so don't nudge the user to re-authorize. Surface as a gateway error.
			h.logger.Warn("resolve connection token failed", zap.String("slug", slug), zap.Error(err))
			writeJSONError(w, http.StatusBadGateway, "failed to obtain connection credentials")
			return
		}
		creds = token
	}

	// Build upstream request.
	upstreamURL, err := parsePublicHTTPURL(conn.BaseUrl + req.Path)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid upstream URL: "+err.Error())
		return
	}
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}

	upstream, err := http.NewRequestWithContext(r.Context(), method, upstreamURL.String(), bodyReader)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid upstream request: %v", err))
		return
	}
	if req.Body != "" {
		upstream.Header.Set("Content-Type", "application/json")
	}

	// Header layering: platform baseline → connection-declared Headers →
	// per-call ProxyRequest.Headers. Each layer merges per-key on top of
	// the previous; an explicit empty-string value at any layer removes
	// the key entirely. Auth injection runs last so it always wins —
	// otherwise a sloppy `Authorization` in per-call headers would
	// silently bypass the credential proxy.
	upstream.Header.Set("User-Agent", webfetch.UserAgent)
	applyHeaderMap(upstream.Header, decodeConnHeaders(conn.Headers))
	applyHeaderMap(upstream.Header, req.Headers)

	// Inject auth (no-op for auth_mode='none' — `creds` is empty and the
	// injection config is irrelevant).
	if !noAuth {
		InjectAuth(upstream, conn.AuthInjection, creds)
	}

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

	// Cap the proxied response at MaxBufferedResponseBytes — same ceiling
	// the agent SDK applies to conn.Request. Defense in depth: without
	// this, a runaway upstream can OOM the agent process (which does
	// io.ReadAll on its end). The +1 sentinel detects overflow so we can
	// log loudly; the early close lets the agent's reader surface a
	// short-read as a clean "upstream truncated" error.
	written, err := io.Copy(w, io.LimitReader(resp.Body, int64(MaxBufferedResponseBytes)+1))
	if err != nil {
		h.logger.Warn("connection proxy stream copy",
			zap.String("slug", conn.Slug),
			zap.Int64("bytes_written", written),
			zap.Error(err))
		return
	}
	if written > int64(MaxBufferedResponseBytes) {
		h.logger.Warn("connection proxy hit hard cap",
			zap.String("slug", conn.Slug),
			zap.Int64("max_bytes", int64(MaxBufferedResponseBytes)))
	}
}

// applyHeaderMap merges m into h, using the empty-string-as-delete rule:
// a key whose value is "" removes any header of that name set by a lower
// layer. Non-empty values overwrite per-key.
func applyHeaderMap(h http.Header, m map[string]string) {
	for k, v := range m {
		if v == "" {
			h.Del(k)
			continue
		}
		h.Set(k, v)
	}
}

// decodeConnHeaders unmarshals the connection's headers jsonb column.
// A malformed value is treated as "no overrides" — the platform
// baseline and per-call layers still apply — and logged at the call
// site rather than here so we don't pull a logger into a pure helper.
func decodeConnHeaders(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

// InjectAuth adds credentials to the upstream request based on the auth injection config.
func InjectAuth(req *http.Request, authInjectionJSON []byte, creds string) {
	var injection agentsdk.AuthInjection
	if err := json.Unmarshal(authInjectionJSON, &injection); err != nil {
		return
	}

	switch injection.Type {
	case agentsdk.AuthInjectBearer:
		req.Header.Set("Authorization", "Bearer "+creds)
	case agentsdk.AuthInjectAPIKey:
		name := injection.Name
		if name == "" {
			name = "X-API-Key"
		}
		req.Header.Set(name, creds)
	case agentsdk.AuthInjectPathPrefix:
		req.URL.Path = "/" + creds + req.URL.Path
	case agentsdk.AuthInjectQueryParam:
		name := injection.Name
		if name == "" {
			name = "token"
		}
		q := req.URL.Query()
		q.Set(name, creds)
		req.URL.RawQuery = q.Encode()
	}
}
