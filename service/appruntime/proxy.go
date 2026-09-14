package appruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/airlock/apperr"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/sol/webfetch"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

func (h *Service) ServiceProxy(ctx context.Context, slug string, req wire.ProxyRequest) (*http.Response, error) {
	agentID, err := h.admit(ctx, dbq.New(h.db.Pool()))
	if err != nil {
		return nil, err
	}
	q := dbq.New(h.db.Pool())
	// Resolve the agent's connection need to its bound resource. The proxy and
	// the credential refresh below key on the resolved resource's own id, so
	// one connection can back many agents' bindings.
	conn, err := q.ResolveBoundConnection(ctx, dbq.ResolveBoundConnectionParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apperr.Detail(apperr.ErrNotFound, "connection not bound")
		}
		h.logger.Error("resolve connection failed", zap.Error(err))
		return nil, fmt.Errorf("%s: %w", "failed to get connection", ErrUpstream)
	}
	// auth_mode='none' connections proxy without credentials — no token
	// lookup, no decrypt, no injection. Public APIs (MediaWiki, etc.)
	// declared with ConnectionAuthNone land here.
	noAuth := conn.AuthMode == string(wire.ConnectionAuthNone)

	// Resolve credentials (skipped for auth_mode='none'). EnsureConnectionToken
	// renews an expired access token on demand, under a row lock, so a lapsed
	// token self-heals on this very call instead of waiting for the background
	// refresh tick. Only a genuinely unrecoverable connection (no token / no
	// refresh token / provider-revoked) returns 402 auth_required; the agent's
	// system prompt already routes the user to the settings page, so the body
	// carries only slug/connName, not a raw OAuth URL.
	var creds string
	if !noAuth {
		token, err := oauth.EnsureConnectionToken(ctx, h.db, h.encryptor, h.oauthClient, h.logger, toPgUUID(agentID), slug, conn.ID, time.Now())
		switch {
		case errors.Is(err, oauth.ErrNeedsReauth):
			return nil, &AuthorizationRequired{Details: map[string]string{
				"error":    "auth_required",
				"slug":     conn.Slug,
				"connName": conn.Name,
				"message":  fmt.Sprintf("%s needs authorization", conn.Name),
			}}
		case err != nil:
			// Transient refresh/decrypt failure — the connection may recover,
			// so don't nudge the user to re-authorize. Surface as a gateway error.
			h.logger.Warn("resolve connection token failed", zap.String("slug", slug), zap.Error(err))
			return nil, fmt.Errorf("%s: %w", "failed to obtain connection credentials", ErrUpstream)
		}
		creds = token
	}

	// Build upstream request.
	upstreamURL, err := runtimesvc.ConnectionUpstreamURL(h.httpNetwork, conn.BaseUrl, req.Path)
	if err != nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", "invalid upstream URL: "+err.Error())
	}
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}

	upstream, err := http.NewRequestWithContext(ctx, method, upstreamURL.String(), bodyReader)
	if err != nil {
		return nil, apperr.Detail(apperr.ErrInvalidInput, "%s", fmt.Sprintf("invalid upstream request: %v", err))
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
	runtimesvc.ApplyHeaderMap(upstream.Header, runtimesvc.DecodeConnHeaders(conn.Headers))
	runtimesvc.ApplyHeaderMap(upstream.Header, req.Headers)

	// Inject auth (no-op for auth_mode='none' — `creds` is empty and the
	// injection config is irrelevant).
	if !noAuth {
		runtimesvc.InjectAuth(upstream, conn.AuthInjection, creds)
	}

	resp, err := h.httpNetwork.Client(30 * time.Second).Do(upstream)
	if err != nil {
		h.logger.Error("proxy upstream request failed", zap.Error(err))
		return nil, fmt.Errorf("%s: %w", "upstream request failed", ErrUpstream)
	}

	return resp, nil
}
