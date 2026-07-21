// Package execendpoints owns the operator-facing CRUD + test of
// per-agent SSH exec endpoints (declared by the agent via
// RegisterExecEndpoint, configured by the operator here).
package execendpoints

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/execproxy"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/needs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Dialer is the subset of execproxy.SSHDialer the service uses.
type Dialer interface {
	Exec(ctx context.Context, ep *dbq.AgentExecEndpoint, req execproxy.ExecRequest, w http.ResponseWriter) error
	EvictCache(id uuid.UUID)
}

// Pool is the minimal subset of *pgxpool.Pool dbq.New accepts. Kept
// generic so the constructor matches the existing handler-side pattern.
type Pool interface {
	dbq.DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

type Service struct {
	pool    Pool
	queries *dbq.Queries
	secrets secrets.Store
	dialer  Dialer
	logger  *zap.Logger
}

func New(pool Pool, store secrets.Store, dialer Dialer, logger *zap.Logger) *Service {
	if pool == nil {
		panic("execendpoints: pool is required")
	}
	if store == nil {
		panic("execendpoints: secrets store is required")
	}
	if dialer == nil {
		panic("execendpoints: dialer is required")
	}
	if logger == nil {
		panic("execendpoints: logger is required")
	}
	return &Service{
		pool:    pool,
		queries: dbq.New(pool),
		secrets: store,
		dialer:  dialer,
		logger:  logger.Named("exec-endpoints"),
	}
}

// resolveEndpoint maps (agentID, need slug) to the bound exec-endpoint resource
// — the row an agent reaches through its need's binding. An unbound need is
// "not found".
func (s *Service) resolveEndpoint(ctx context.Context, agentID uuid.UUID, slug string) (dbq.AgentExecEndpoint, error) {
	ep, err := s.queries.ResolveBoundExecEndpoint(ctx, dbq.ResolveBoundExecEndpointParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
		Slug:    slug,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.AgentExecEndpoint{}, service.ErrNotFound
	}
	return ep, err
}

// ConfigureRequest is the input for Configure. Port=0 defaults to 22.
type ConfigureRequest struct {
	Host        string
	Port        int32
	SSHUser     string
	DisplayName string
	CreateNew   bool
}

// TestResult is the parsed outcome of running `whoami` over the
// configured SSH transport, ready to render in the operator UI.
type TestResult struct {
	OK         bool
	ExitCode   int
	DurationMs int64
	Stdout     string
	Stderr     string
	Error      string
}

// List returns every exec-endpoint need the agent declares, joined to its bound
// resource (if configured) — keyed by the agent's need slug.
func (s *Service) List(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]dbq.ListExecNeedsByAgentRow, error) {
	if err := authz.Authorize(ctx, s.queries, p, authz.AgentGet, agentID); err != nil {
		return nil, err
	}
	rows, err := s.queries.ListExecNeedsByAgent(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list exec endpoints failed", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// Configure persists host/port/user for a declared endpoint and generates a
// keypair on first configure. The exec-endpoint resource is created (owned by
// the configuring principal) and bound to the agent's need on first configure.
// ErrInvalidInput for bad input, ErrNotFound when the slug wasn't declared.
func (s *Service) Configure(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string, req ConfigureRequest) (dbq.AgentExecEndpoint, error) {
	if err := authz.Authorize(ctx, s.queries, p, authz.AgentExecEndpoints, agentID); err != nil {
		return dbq.AgentExecEndpoint{}, err
	}
	if strings.TrimSpace(req.Host) == "" {
		return dbq.AgentExecEndpoint{}, service.Detail(service.ErrInvalidInput, "host is required")
	}
	if strings.TrimSpace(req.SSHUser) == "" {
		return dbq.AgentExecEndpoint{}, service.Detail(service.ErrInvalidInput, "sshUser is required")
	}
	if req.Port == 0 {
		req.Port = 22
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return dbq.AgentExecEndpoint{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.GetAgentByIDForUpdate(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return dbq.AgentExecEndpoint{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentExecEndpoints, agentID); err != nil {
		return dbq.AgentExecEndpoint{}, err
	}
	resourceID, err := needs.CreateForNeed(ctx, q, p, agentID, "exec_endpoint", slug, req.DisplayName, req.CreateNew)
	if err != nil {
		return dbq.AgentExecEndpoint{}, err
	}
	ep, err := q.GetExecEndpointByIDForUpdate(ctx, pgtype.UUID{Bytes: resourceID, Valid: true})
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return dbq.AgentExecEndpoint{}, service.Detail(service.ErrNotFound, "exec endpoint not declared by the agent")
		}
		s.logger.Error("get exec endpoint", zap.Error(err))
		return dbq.AgentExecEndpoint{}, err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, "exec_endpoint", resourceID); err != nil {
		return dbq.AgentExecEndpoint{}, err
	}
	if err := q.ConfigureExecEndpointSSHByID(ctx, dbq.ConfigureExecEndpointSSHByIDParams{
		ID:      ep.ID,
		Host:    pgtype.Text{String: req.Host, Valid: true},
		Port:    pgtype.Int4{Int32: req.Port, Valid: true},
		SshUser: pgtype.Text{String: req.SSHUser, Valid: true},
	}); err != nil {
		s.logger.Error("configure exec endpoint", zap.Error(err))
		return dbq.AgentExecEndpoint{}, err
	}
	if !ep.PrivateKeyRef.Valid || ep.PrivateKeyRef.String == "" {
		if _, err := s.generateAndStoreKeypair(ctx, q, agentID, slug, ep); err != nil {
			s.logger.Error("keypair generation on configure", zap.Error(err))
			// No sentinel: surface as a plain error so HTTPStatus returns 500.
			// The handler renders "configured but keypair generation failed".
			return dbq.AgentExecEndpoint{}, errKeypairAfterConfigure
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.AgentExecEndpoint{}, err
	}
	s.dialer.EvictCache(uuid.UUID(ep.ID.Bytes))
	return s.resolveEndpoint(ctx, agentID, slug)
}

// RotateKeypair mints a new ED25519 keypair, replaces the secrets-store
// ref, and evicts the cached SSH client.
func (s *Service) RotateKeypair(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) (dbq.AgentExecEndpoint, error) {
	if err := authz.Authorize(ctx, s.queries, p, authz.AgentExecEndpoints, agentID); err != nil {
		return dbq.AgentExecEndpoint{}, err
	}
	ep, err := s.resolveEndpoint(ctx, agentID, slug)
	if err != nil {
		if !errors.Is(err, service.ErrNotFound) {
			s.logger.Error("get exec endpoint", zap.Error(err))
		}
		return dbq.AgentExecEndpoint{}, err
	}
	if err := authz.AuthorizeResource(ctx, s.queries, p, authz.ResourceManage, "exec_endpoint", uuid.UUID(ep.ID.Bytes)); err != nil {
		return dbq.AgentExecEndpoint{}, err
	}
	if _, err := s.generateAndStoreKeypair(ctx, s.queries, agentID, slug, ep); err != nil {
		s.logger.Error("keypair rotation", zap.Error(err))
		return dbq.AgentExecEndpoint{}, err
	}
	s.dialer.EvictCache(uuid.UUID(ep.ID.Bytes))
	return s.resolveEndpoint(ctx, agentID, slug)
}

// UnpinHostKey clears the TOFU-pinned host key on this endpoint; the
// next successful connect re-pins whatever the remote presents.
func (s *Service) UnpinHostKey(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) error {
	if err := authz.Authorize(ctx, s.queries, p, authz.AgentExecEndpoints, agentID); err != nil {
		return err
	}
	ep, err := s.resolveEndpoint(ctx, agentID, slug)
	if err != nil {
		if !errors.Is(err, service.ErrNotFound) {
			s.logger.Error("get exec endpoint", zap.Error(err))
		}
		return err
	}
	if err := authz.AuthorizeResource(ctx, s.queries, p, authz.ResourceManage, "exec_endpoint", uuid.UUID(ep.ID.Bytes)); err != nil {
		return err
	}
	if err := s.queries.ClearExecEndpointHostKeyByID(ctx, ep.ID); err != nil {
		s.logger.Error("clear host key", zap.Error(err))
		return err
	}
	s.dialer.EvictCache(uuid.UUID(ep.ID.Bytes))
	return nil
}

// Test runs `whoami` through the dialer and parses the buffered NDJSON
// stream into a one-shot TestResult. Caps each captured stream at 4 KiB.
func (s *Service) Test(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) (TestResult, error) {
	if err := authz.Authorize(ctx, s.queries, p, authz.AgentExecEndpoints, agentID); err != nil {
		return TestResult{}, err
	}
	ep, err := s.resolveEndpoint(ctx, agentID, slug)
	if err != nil {
		return TestResult{}, err
	}
	if err := authz.AuthorizeResource(ctx, s.queries, p, authz.ResourceManage, "exec_endpoint", uuid.UUID(ep.ID.Bytes)); err != nil {
		return TestResult{}, err
	}
	const capPerStream = 4 * 1024
	rec := newRecorder(capPerStream)
	execErr := s.dialer.Exec(ctx, &ep, execproxy.ExecRequest{
		Command:   "whoami",
		TimeoutMs: 15000,
	}, rec)
	var res TestResult
	if execErr != nil {
		var pre *execproxy.PreStreamError
		if errors.As(execErr, &pre) {
			res.Error = pre.Message
		} else {
			res.Error = execErr.Error()
		}
		return res, nil
	}
	parseRecorder(rec, &res)
	return res, nil
}

// generateAndStoreKeypair mints + persists a new ED25519 keypair, then
// updates the endpoint row to reference it.
func (s *Service) generateAndStoreKeypair(ctx context.Context, q *dbq.Queries, agentID uuid.UUID, slug string, ep dbq.AgentExecEndpoint) (string, error) {
	kp, err := execproxy.GenerateED25519(agentID.String()[:8], slug)
	if err != nil {
		return "", err
	}
	endpointID := uuid.UUID(ep.ID.Bytes)
	ref, err := s.secrets.Put(ctx, "exec/"+endpointID.String()+"/private_key", kp.PrivatePEM)
	if err != nil {
		return "", err
	}
	if err := q.SetExecEndpointKeypairByID(ctx, dbq.SetExecEndpointKeypairByIDParams{
		ID:               ep.ID,
		PrivateKeyRef:    pgtype.Text{String: ref, Valid: true},
		PublicKeyOpenssh: pgtype.Text{String: strings.TrimRight(kp.PublicOpenSSH, "\n"), Valid: true},
		PublicKeyComment: pgtype.Text{String: kp.Comment, Valid: true},
	}); err != nil {
		return "", err
	}
	return kp.PublicOpenSSH, nil
}

// ErrKeypairAfterConfigure marks the specific 500 condition where the
// row was written but follow-up keypair gen failed.
var ErrKeypairAfterConfigure = errors.New("configured but keypair generation failed")

var errKeypairAfterConfigure = ErrKeypairAfterConfigure

// --- recorder used by Test ---

type recorder struct {
	header     http.Header
	status     int
	buf        []byte
	capPerLine int
}

func newRecorder(capPerLine int) *recorder {
	return &recorder{header: http.Header{}, status: http.StatusOK, capPerLine: capPerLine}
}

func (e *recorder) Header() http.Header { return e.header }
func (e *recorder) WriteHeader(s int)   { e.status = s }
func (e *recorder) Write(b []byte) (int, error) {
	e.buf = append(e.buf, b...)
	return len(b), nil
}

func parseRecorder(rec *recorder, res *TestResult) {
	for _, line := range bytes.Split(rec.buf, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
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
			res.Stdout += truncateForUI(string(data), rec.capPerLine-len(res.Stdout))
		case "stderr":
			data, _ := base64.StdEncoding.DecodeString(env.Data)
			res.Stderr += truncateForUI(string(data), rec.capPerLine-len(res.Stderr))
		case "exit":
			res.OK = env.Code == 0
			res.ExitCode = env.Code
			res.DurationMs = env.DurationMs
		case "error":
			res.Error = env.Kind + ": " + env.Message
		}
	}
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
