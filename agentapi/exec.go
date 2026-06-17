package agentapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/execproxy"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// UpsertExecEndpoint handles PUT /api/agent/exec-endpoints/{slug}.
// Pushed by every container on startup via agentsdk's syncWithAirlock.
// Only writes declaration fields (description, llm_hint, access);
// operator-configured columns (transport, host, ssh_user, private_key,
// host_key) are preserved on conflict so a re-sync of a running agent
// doesn't nuke its operator config.
func (h *Handler) UpsertExecEndpoint(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeJSONError(w, http.StatusBadRequest, "slug is required")
		return
	}

	var def agentsdk.ExecEndpointDef
	if err := readJSON(r, &def); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if def.Description == "" {
		writeJSONError(w, http.StatusBadRequest, "description is required")
		return
	}
	access := string(def.Access)
	if access == "" {
		access = string(agentsdk.AccessAdmin)
	}

	q := dbq.New(h.db.Pool())
	err := q.UpsertExecEndpointDeclaration(r.Context(), dbq.UpsertExecEndpointDeclarationParams{
		AgentID:     toPgUUID(agentID),
		Slug:        slug,
		Description: def.Description,
		LlmHint:     def.LLMHint,
		Access:      access,
	})
	if err != nil {
		h.logger.Error("upsert exec endpoint failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to upsert exec endpoint")
		return
	}

	// Record the agent's need for this exec endpoint (spec = declared
	// template) and bind it to the agent's own resource.
	ep, err := q.GetExecEndpointBySlug(r.Context(), dbq.GetExecEndpointBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		h.logger.Error("get exec endpoint after upsert failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to upsert exec endpoint")
		return
	}
	spec, _ := json.Marshal(map[string]any{"llm_hint": def.LLMHint, "access": access})
	if err := q.UpsertResourceNeed(r.Context(), dbq.UpsertResourceNeedParams{
		AgentID: toPgUUID(agentID), Type: "exec_endpoint", Slug: slug,
		Description: def.Description, SetupInstructions: "", ExpectedUrl: "", ExpectedScopes: "", Spec: spec,
	}); err != nil {
		h.logger.Error("record exec need failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to upsert exec endpoint")
		return
	}
	if err := q.BindExecEndpointNeed(r.Context(), dbq.BindExecEndpointNeedParams{
		AgentID: toPgUUID(agentID), Slug: slug, ResourceID: ep.ID,
	}); err != nil {
		h.logger.Error("bind exec need failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to upsert exec endpoint")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AgentExec handles POST /api/agent/exec/{slug}. Streams the exec
// session's stdout/stderr/exit envelopes back to the agent as NDJSON
// over chunked transfer encoding (see execproxy/ssh.go).
//
// Pre-stream errors (slug not configured, transport not yet supported,
// dial/auth failure) return a JSON error body with an appropriate
// status code; the agent SDK classifies via the status code, not the
// body. Once the first envelope is on the wire, all subsequent failures
// land as terminal "error" envelopes inside the stream.
func (h *Handler) AgentExec(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeJSONError(w, http.StatusBadRequest, "slug is required")
		return
	}

	var req agentsdk.ExecRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Command == "" {
		writeJSONError(w, http.StatusBadRequest, "command is required")
		return
	}

	q := dbq.New(h.db.Pool())
	// Resolve the agent's exec_endpoint need to its bound resource; the SSH
	// dialer reads host/keypair off the resolved row.
	ep, err := q.ResolveBoundExecEndpoint(r.Context(), dbq.ResolveBoundExecEndpointParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "exec endpoint not bound")
			return
		}
		h.logger.Error("resolve exec endpoint failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load exec endpoint")
		return
	}

	stdin, err := base64.StdEncoding.DecodeString(req.StdinB64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid stdinB64")
		return
	}
	h.logger.Debug("agent exec",
		zap.String("endpoint_slug", slug),
		zap.Int("stdin_bytes", len(stdin)),
		zap.Int64("timeout_ms", req.TimeoutMs))

	execErr := h.execDialer.Exec(r.Context(), &ep, execproxy.ExecRequest{
		Command:   req.Command,
		Args:      req.Args,
		Stdin:     stdin,
		TimeoutMs: req.TimeoutMs,
	}, w)
	if execErr != nil {
		// Exec returns PreStreamError when nothing has been written to
		// w yet. Map .Status to the response code.
		var pre *execproxy.PreStreamError
		if errors.As(execErr, &pre) {
			writeJSONError(w, pre.Status, pre.Message)
			return
		}
		// Anything else means the stream was already in flight and the
		// dialer emitted a terminal "error" envelope — no further
		// response action needed.
		h.logger.Warn("agent exec returned post-stream error",
			zap.String("endpoint_slug", slug),
			zap.Error(execErr))
	}

	// Best-effort: bump last_used_at so the operator UI shows freshness.
	// Background ctx so we don't lose the write if the agent disconnects
	// the moment the stream finishes.
	_ = q.TouchExecEndpointLastUsed(context.Background(), ep.ID)
}

// dbqTOFUPinner adapts the sqlc queries into the execproxy.TOFUPinner
// interface so the dialer can persist freshly-observed host keys without
// importing dbq itself.
type dbqTOFUPinner struct {
	pool dbqPool
}

type dbqPool interface {
	dbq.DBTX
}

// NewTOFUPinner constructs a TOFUPinner backed by the airlock pgx pool.
// Each call opens a one-shot Queries so concurrent pin calls don't
// share state.
func NewTOFUPinner(pool dbqPool) *dbqTOFUPinner { return &dbqTOFUPinner{pool: pool} }

func (p *dbqTOFUPinner) PinHostKey(ctx context.Context, endpointID uuid.UUID, hostKeyOpenSSH string) error {
	return dbq.New(p.pool).SetExecEndpointHostKey(ctx, dbq.SetExecEndpointHostKeyParams{
		ID:             toPgUUID(endpointID),
		HostKeyOpenssh: pgText(hostKeyOpenSSH),
	})
}
