package api

import (
	"net/http"
	"strings"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"go.uber.org/zap"
)

// CaddyAskHandler validates on-demand TLS requests from Caddy.
// Caddy calls GET /caddy/ask?domain=foo.stage.airlock.run before
// issuing a certificate. We return 200 if the subdomain belongs
// to a known agent, 403 otherwise.
type CaddyAskHandler struct {
	db          *db.DB
	agentDomain string // e.g. "stage.airlock.run"
	logger      *zap.Logger
}

func (h *CaddyAskHandler) Ask(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeError(w, http.StatusForbidden, "missing domain")
		return
	}

	// Bare domain — allow (frontend).
	if domain == h.agentDomain {
		w.WriteHeader(http.StatusOK)
		return
	}

	suffix := "." + h.agentDomain
	if !strings.HasSuffix(domain, suffix) {
		h.logger.Debug("domain not under agent domain", zap.String("domain", domain))
		writeError(w, http.StatusForbidden, "unknown domain")
		return
	}

	slug := strings.TrimSuffix(domain, suffix)
	if slug == "" {
		// Bare domain — allow (handled by named Caddy blocks).
		w.WriteHeader(http.StatusOK)
		return
	}

	// Reserved infrastructure subdomains — always allow.
	switch slug {
	case "api", "s3":
		w.WriteHeader(http.StatusOK)
		return
	}

	// Check if agent exists.
	q := dbq.New(h.db.Pool())
	_, err := q.GetAgentBySlug(r.Context(), slug)
	if err != nil {
		h.logger.Debug("unknown agent slug", zap.String("slug", slug), zap.Error(err))
		writeError(w, http.StatusForbidden, "unknown agent")
		return
	}

	w.WriteHeader(http.StatusOK)
}
