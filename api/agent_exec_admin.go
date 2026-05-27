package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/execproxy"
	"github.com/airlockrun/airlock/secrets"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// execEndpointsHandler is the operator-facing handler family for
// /api/v1/agents/{agentID}/exec-endpoints/{slug}. List + Configure +
// Rotate + Unpin + Test. Member-of-agent check happens in the route
// group middleware.
type execEndpointsHandler struct {
	queries *dbq.Queries
	secrets secrets.Store
	dialer  execDialerService
	logger  *zap.Logger
}

func newExecEndpointsHandler(pool dbqPool, store secrets.Store, dialer execDialerService, logger *zap.Logger) *execEndpointsHandler {
	return &execEndpointsHandler{
		queries: dbq.New(pool),
		secrets: store,
		dialer:  dialer,
		logger:  logger.Named("exec-endpoints"),
	}
}

// execEndpointDTO is the wire shape the operator UI consumes. Mirrors
// the row layout but with strings instead of pgtype values and the
// host-key SHA256 fingerprint pre-computed for display.
type execEndpointDTO struct {
	ID                 string `json:"id"`
	Slug               string `json:"slug"`
	Description        string `json:"description"`
	LLMHint            string `json:"llmHint"`
	Access             string `json:"access"`
	Transport          string `json:"transport"`
	Host               string `json:"host"`
	Port               int32  `json:"port"`
	SSHUser            string `json:"sshUser"`
	PublicKeyOpenSSH   string `json:"publicKeyOpenssh"`
	PublicKeyComment   string `json:"publicKeyComment"`
	HostKeyFingerprint string `json:"hostKeyFingerprint"`
	HostKeyPinnedAt    string `json:"hostKeyPinnedAt"`
	LastUsedAt         string `json:"lastUsedAt"`
}

func rowToDTO(ep dbq.AgentExecEndpoint) execEndpointDTO {
	dto := execEndpointDTO{
		ID:               uuid.UUID(ep.ID.Bytes).String(),
		Slug:             ep.Slug,
		Description:      ep.Description,
		LLMHint:          ep.LlmHint,
		Access:           ep.Access,
		Transport:        ep.Transport.String,
		Host:             ep.Host.String,
		SSHUser:          ep.SshUser.String,
		PublicKeyOpenSSH: ep.PublicKeyOpenssh.String,
		PublicKeyComment: ep.PublicKeyComment.String,
	}
	if ep.Port.Valid {
		dto.Port = ep.Port.Int32
	}
	if ep.HostKeyOpenssh.Valid && ep.HostKeyOpenssh.String != "" {
		dto.HostKeyFingerprint = execproxy.HostKeyFingerprint(ep.HostKeyOpenssh.String)
	}
	if ep.HostKeyPinnedAt.Valid {
		dto.HostKeyPinnedAt = ep.HostKeyPinnedAt.Time.UTC().Format(time.RFC3339)
	}
	if ep.LastUsedAt.Valid {
		dto.LastUsedAt = ep.LastUsedAt.Time.UTC().Format(time.RFC3339)
	}
	return dto
}

// List handles GET /api/v1/agents/{agentID}/exec-endpoints.
func (h *execEndpointsHandler) List(w http.ResponseWriter, r *http.Request) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	rows, err := h.queries.ListExecEndpointsByAgent(r.Context(), toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list exec endpoints failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to list exec endpoints")
		return
	}
	out := make([]execEndpointDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToDTO(row))
	}
	writeJSON(w, http.StatusOK, out)
}

// configureRequest is the body of PUT
// /api/v1/agents/{agentID}/exec-endpoints/{slug}. Operator supplies
// transport target; airlock generates the keypair if one doesn't exist
// yet on this endpoint.
type configureRequest struct {
	Host    string `json:"host"`
	Port    int32  `json:"port"`
	SSHUser string `json:"sshUser"`
}

// Configure handles PUT /api/v1/agents/{agentID}/exec-endpoints/{slug}.
// Sets host/port/user, generating a keypair on first configure.
func (h *execEndpointsHandler) Configure(w http.ResponseWriter, r *http.Request) {
	agentID, slug, ok := parseAgentSlug(w, r)
	if !ok {
		return
	}
	var req configureRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Host) == "" {
		writeJSONError(w, http.StatusBadRequest, "host is required")
		return
	}
	if strings.TrimSpace(req.SSHUser) == "" {
		writeJSONError(w, http.StatusBadRequest, "sshUser is required")
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}

	ep, err := h.queries.GetExecEndpointBySlug(r.Context(), dbq.GetExecEndpointBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "exec endpoint not declared by the agent")
			return
		}
		h.logger.Error("get exec endpoint", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load exec endpoint")
		return
	}

	if err := h.queries.ConfigureExecEndpointSSH(r.Context(), dbq.ConfigureExecEndpointSSHParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
		Host:    pgText(req.Host),
		Port:    pgInt4(req.Port),
		SshUser: pgText(req.SSHUser),
	}); err != nil {
		h.logger.Error("configure exec endpoint", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to configure exec endpoint")
		return
	}

	// First configure → generate keypair. Subsequent configures keep
	// the existing one (operators use the dedicated rotate endpoint).
	if !ep.PrivateKeyRef.Valid || ep.PrivateKeyRef.String == "" {
		if _, err := h.generateAndStoreKeypair(r.Context(), agentID, slug); err != nil {
			h.logger.Error("keypair generation on configure", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "configured but keypair generation failed")
			return
		}
	}

	h.dialer.EvictCache(uuid.UUID(ep.ID.Bytes))

	refreshed, _ := h.queries.GetExecEndpointBySlug(r.Context(), dbq.GetExecEndpointBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	writeJSON(w, http.StatusOK, rowToDTO(refreshed))
}

// RotateKeypair handles POST /api/v1/agents/{agentID}/exec-endpoints/{slug}/rotate-keypair.
// Generates a fresh ED25519 keypair, persists it (replacing the old
// secrets-store ref), evicts the cached client. Operator must paste the
// new public key into the target's authorized_keys; the old line can
// be grep'd by the dated comment.
func (h *execEndpointsHandler) RotateKeypair(w http.ResponseWriter, r *http.Request) {
	agentID, slug, ok := parseAgentSlug(w, r)
	if !ok {
		return
	}
	ep, err := h.queries.GetExecEndpointBySlug(r.Context(), dbq.GetExecEndpointBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "exec endpoint not found")
			return
		}
		h.logger.Error("get exec endpoint", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load exec endpoint")
		return
	}

	if _, err := h.generateAndStoreKeypair(r.Context(), agentID, slug); err != nil {
		h.logger.Error("keypair rotation", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to rotate keypair")
		return
	}
	h.dialer.EvictCache(uuid.UUID(ep.ID.Bytes))

	refreshed, _ := h.queries.GetExecEndpointBySlug(r.Context(), dbq.GetExecEndpointBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	writeJSON(w, http.StatusOK, rowToDTO(refreshed))
}

// UnpinHostKey handles POST /api/v1/agents/{agentID}/exec-endpoints/{slug}/unpin-host-key.
// Clears the pinned host key — the next successful connect TOFU-pins
// whatever the remote presents. Operators use this after a known-good
// rotation on the target box.
func (h *execEndpointsHandler) UnpinHostKey(w http.ResponseWriter, r *http.Request) {
	agentID, slug, ok := parseAgentSlug(w, r)
	if !ok {
		return
	}
	ep, err := h.queries.GetExecEndpointBySlug(r.Context(), dbq.GetExecEndpointBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "exec endpoint not found")
			return
		}
		h.logger.Error("get exec endpoint", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load exec endpoint")
		return
	}
	if err := h.queries.ClearExecEndpointHostKey(r.Context(), dbq.ClearExecEndpointHostKeyParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	}); err != nil {
		h.logger.Error("clear host key", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to clear host key")
		return
	}
	h.dialer.EvictCache(uuid.UUID(ep.ID.Bytes))
	w.WriteHeader(http.StatusNoContent)
}

// testResponse is the body of POST .../test — surfaces enough for the
// operator UI to render success / failure inline.
type testResponse struct {
	OK         bool   `json:"ok"`
	ExitCode   int    `json:"exitCode"`
	DurationMs int64  `json:"durationMs"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Test handles POST /api/v1/agents/{agentID}/exec-endpoints/{slug}/test.
// Runs `whoami` through the SSH dialer; doubles as the TOFU-pin trigger
// when the operator wants to verify a freshly-configured target.
//
// Unlike AgentExec, this handler buffers the streamed response into a
// small in-memory recorder so we can return one JSON object with the
// outcome. Capped at 4 KiB per stream — `whoami` is tiny; we cut off
// long output rather than stream it through the operator UI.
func (h *execEndpointsHandler) Test(w http.ResponseWriter, r *http.Request) {
	agentID, slug, ok := parseAgentSlug(w, r)
	if !ok {
		return
	}
	ep, err := h.queries.GetExecEndpointBySlug(r.Context(), dbq.GetExecEndpointBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "exec endpoint not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to load exec endpoint")
		return
	}

	rec := newExecRecorder(4 * 1024)
	execErr := h.dialer.Exec(r.Context(), &ep, execproxy.ExecRequest{
		Command:   "whoami",
		TimeoutMs: 15000,
	}, rec)

	var resp testResponse
	if execErr != nil {
		var pre *execproxy.PreStreamError
		if errors.As(execErr, &pre) {
			resp.Error = pre.Message
		} else {
			resp.Error = execErr.Error()
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	// Parse the buffered NDJSON envelopes the recorder captured.
	parseExecRecorder(rec, &resp)
	writeJSON(w, http.StatusOK, resp)
}

// generateAndStoreKeypair mints a fresh ED25519 keypair, encrypts the
// private key via secrets.Store, and persists the public key + comment
// + ref onto the endpoint row. Returns the public key for the caller
// to surface inline; the operator doesn't need it because the
// follow-up GET shows the same value.
func (h *execEndpointsHandler) generateAndStoreKeypair(ctx context.Context, agentID uuid.UUID, slug string) (string, error) {
	kp, err := execproxy.GenerateED25519(agentID.String()[:8], slug)
	if err != nil {
		return "", err
	}
	// Endpoint ID is part of the secrets ref path so each rotation
	// produces a fresh ref — old refs (if any other code persisted
	// them) keep decrypting against the same key version.
	ep, err := h.queries.GetExecEndpointBySlug(ctx, dbq.GetExecEndpointBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		return "", err
	}
	endpointID := uuid.UUID(ep.ID.Bytes)
	ref, err := h.secrets.Put(ctx, "exec/"+endpointID.String()+"/private_key", kp.PrivatePEM)
	if err != nil {
		return "", err
	}
	if err := h.queries.SetExecEndpointKeypair(ctx, dbq.SetExecEndpointKeypairParams{
		AgentID:          toPgUUID(agentID),
		Slug:             slug,
		PrivateKeyRef:    pgText(ref),
		PublicKeyOpenssh: pgText(strings.TrimRight(kp.PublicOpenSSH, "\n")),
		PublicKeyComment: pgText(kp.Comment),
	}); err != nil {
		return "", err
	}
	return kp.PublicOpenSSH, nil
}

// parseAgentSlug extracts and validates the agent ID + slug from the
// chi route params. Writes the error response itself on failure;
// returns ok=false so the caller short-circuits.
func parseAgentSlug(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	agentID, err := uuid.Parse(chi.URLParam(r, "agentID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid agent id")
		return uuid.Nil, "", false
	}
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeJSONError(w, http.StatusBadRequest, "slug is required")
		return uuid.Nil, "", false
	}
	return agentID, slug, true
}

// --- recorder used by Test ---

// execRecorder is an http.ResponseWriter that buffers up to capPerStream
// bytes of the streamed exec body for later parsing. We use it for the
// connection-test endpoint where we want one JSON outcome instead of
// streaming envelopes to the operator UI.
type execRecorder struct {
	header     http.Header
	status     int
	buf        []byte
	capPerLine int
}

func newExecRecorder(capPerLine int) *execRecorder {
	return &execRecorder{header: http.Header{}, status: http.StatusOK, capPerLine: capPerLine}
}

func (e *execRecorder) Header() http.Header { return e.header }
func (e *execRecorder) WriteHeader(s int)   { e.status = s }
func (e *execRecorder) Write(b []byte) (int, error) {
	e.buf = append(e.buf, b...)
	return len(b), nil
}

// parseExecRecorder walks the recorded NDJSON envelopes and fills resp.
// Best-effort: malformed envelopes are skipped, not surfaced as errors —
// the test endpoint is for happy-path validation, deep diagnosis belongs
// in the runs log.
func parseExecRecorder(rec *execRecorder, resp *testResponse) {
	for _, line := range splitLines(rec.buf) {
		var env struct {
			Type       string `json:"type"`
			Data       string `json:"data"`
			Code       int    `json:"code"`
			DurationMs int64  `json:"durationMs"`
			Kind       string `json:"kind"`
			Message    string `json:"message"`
		}
		if err := json.Unmarshal(line, &env); err != nil {
			continue
		}
		switch env.Type {
		case "stdout":
			data, _ := base64.StdEncoding.DecodeString(env.Data)
			resp.Stdout += truncateForUI(string(data), rec.capPerLine-len(resp.Stdout))
		case "stderr":
			data, _ := base64.StdEncoding.DecodeString(env.Data)
			resp.Stderr += truncateForUI(string(data), rec.capPerLine-len(resp.Stderr))
		case "exit":
			resp.OK = env.Code == 0
			resp.ExitCode = env.Code
			resp.DurationMs = env.DurationMs
		case "error":
			resp.Error = env.Kind + ": " + env.Message
		}
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func truncateForUI(s string, remaining int) string {
	if remaining <= 0 {
		return ""
	}
	if len(s) <= remaining {
		return s
	}
	return s[:remaining]
}

// Suppress unused-import warning for pgtype.
var _ pgtype.UUID
