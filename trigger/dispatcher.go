// Package trigger provides services that trigger agent containers in response
// to external events: webhooks, cron schedules, and channel messages.
package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	localepkg "github.com/airlockrun/airlock/locale"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// PromptHTTPCeiling is the absolute cap on a prompt run's outbound HTTP
// request. Generous on purpose: prompt runs may legitimately stream for
// many minutes (long tool chains, slow LLMs); the user cancels manually
// via DELETE /api/v1/runs/{runID} when they want to stop earlier. Cron and
// webhook callers pass their own (typically shorter) timeout.
const PromptHTTPCeiling = 30 * time.Minute

// Sentinel errors from EnsureRunning for agents that exist but aren't in a
// runnable state. Callers map these to a surface-appropriate response
// (409 on HTTP, an in-chat notice on bridges, a JSON-RPC error on MCP)
// instead of a generic 500. Both are expected operator states, not faults.
var (
	// ErrAgentStopped — the agent is parked via /stop and only a manual
	// /start resumes it; EnsureRunning refuses to auto-start it.
	ErrAgentStopped = errors.New("agent is stopped")
	// ErrAgentNoImage — the agent has never finished a build, so there is
	// no container image to run.
	ErrAgentNoImage   = errors.New("agent has no image")
	ErrAgentDeploying = errors.New("agent deployment is starting")
	ErrJobLeaseLost   = errors.New("background job delivery lease lost")
)

// notRunnableBridgeReply maps a not-runnable sentinel to a chat-friendly
// reply for bridge surfaces. ok is false for any other error, so callers
// fall through to their normal error return. The reply is plain prose —
// a bridge user can't /start an agent, so it points them at an admin.
func notRunnableBridgeReply(err error) (reply string, ok bool) {
	switch {
	case errors.Is(err, ErrAgentStopped):
		return "This agent is stopped. An admin needs to start it before it can reply.", true
	case errors.Is(err, ErrAgentNoImage):
		return "This agent hasn't finished building yet. Try again once it's ready.", true
	default:
		return "", false
	}
}

// runState tracks an in-flight run for cancellation.
type runState struct {
	cancel context.CancelFunc
}

// Dispatcher ensures agent containers are running and forwards HTTP requests to them.
type Dispatcher struct {
	cfg                *config.Config
	db                 *db.DB
	containers         container.ContainerManager
	encryptor          secrets.Store
	logger             *zap.Logger
	runtimeForwardGate func(context.Context, uuid.UUID) (bool, error)
	chat               PromptRuntime

	// In-flight per-run state registry. Populated when webhook and job
	// execution starts streaming from the agent,
	// removed when the response body is closed (after publishRunEvents
	// drains it). CancelRun(runID) fires the registered cancel func,
	// which aborts the outbound HTTP request — the agent's r.Context()
	// then cancels, vm.Interrupt fires, and the agent finalizes via its
	// detached /api/agent/run/complete POST.
	mu       sync.Mutex
	inFlight map[uuid.UUID]*runState
}

// NewDispatcher creates a Dispatcher.
func NewDispatcher(cfg *config.Config, database *db.DB, containers container.ContainerManager, enc secrets.Store, logger *zap.Logger) *Dispatcher {
	d := &Dispatcher{
		cfg:        cfg,
		db:         database,
		containers: containers,
		encryptor:  enc,
		logger:     logger,
		inFlight:   make(map[uuid.UUID]*runState),
	}
	d.runtimeForwardGate = func(ctx context.Context, agentID uuid.UUID) (bool, error) {
		tx, err := database.Pool().Begin(ctx)
		if err != nil {
			return false, err
		}
		defer tx.Rollback(ctx)
		q := dbq.New(tx)
		agent, err := q.GetAgentByIDForUpdate(ctx, toPgUUID(agentID))
		if err != nil {
			return false, err
		}
		blocked := false
		if agent.JobDispatchPausedBuildID.Valid {
			build, err := q.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{
				BuildID: agent.JobDispatchPausedBuildID, AgentID: agent.ID,
			})
			if err != nil {
				return false, err
			}
			if build.DeploymentPhase == "starting" {
				blocked = true
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		return blocked, nil
	}
	return d
}

// CancelRun aborts the in-flight outbound request for the given run, if any.
// Returns true if a cancel was fired. Idempotent — repeat calls and calls
// for runs that already finished are no-ops.
func (d *Dispatcher) CancelRun(runID uuid.UUID) bool {
	if d.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		rows, err := dbq.New(d.db.Pool()).RequestConversationRunCancellation(ctx, toPgUUID(runID))
		cancel()
		if err != nil {
			d.logger.Error("persist chat cancellation", zap.Error(err))
		}
		if rows > 0 {
			return true
		}
	}
	d.mu.Lock()
	state, ok := d.inFlight[runID]
	delete(d.inFlight, runID)
	d.mu.Unlock()
	if ok {
		state.cancel()
	}
	return ok
}

// InFlightIDs returns a snapshot of currently-tracked run IDs. Used by the
// stuck-run sweeper so it doesn't race the dispatcher and prematurely
// terminate a still-live run.
func (d *Dispatcher) InFlightIDs() []uuid.UUID {
	d.mu.Lock()
	defer d.mu.Unlock()
	ids := make([]uuid.UUID, 0, len(d.inFlight))
	for id := range d.inFlight {
		ids = append(ids, id)
	}
	return ids
}

// registerInFlight stores the run's cancel hook so CancelRun can fire it.
func (d *Dispatcher) registerInFlight(runID uuid.UUID, cancel context.CancelFunc) {
	d.mu.Lock()
	d.inFlight[runID] = &runState{cancel: cancel}
	d.mu.Unlock()
}

func (d *Dispatcher) deregisterInFlight(runID uuid.UUID) {
	d.mu.Lock()
	delete(d.inFlight, runID)
	d.mu.Unlock()
}

// runBodyCloser owns the detached request context and cancel-registry entry.
// Closing it releases both when a run finishes naturally.
type runBodyCloser struct {
	io.ReadCloser
	dispatcher *Dispatcher
	runID      uuid.UUID
	cancel     context.CancelFunc
}

func (r *runBodyCloser) Close() error {
	r.dispatcher.deregisterInFlight(r.runID)
	r.cancel()
	return r.ReadCloser.Close()
}

// busyCloser wraps the agent's response body so closing it marks the
// agent container idle. Paired with the MarkBusy call in forward: the
// container is held busy — exempt from idle reaping — for the whole
// life of the streamed response, however long the run takes.
type busyCloser struct {
	io.ReadCloser
	containers          container.ContainerManager
	agentID             uuid.UUID
	queries             *dbq.Queries
	invocationToken     string
	stopInvocationClose func() bool
}

func (b *busyCloser) Close() error {
	b.containers.MarkIdle(b.agentID)
	b.stopInvocationClose()
	return errors.Join(b.ReadCloser.Close(), execution.CloseInvocation(b.queries, b.invocationToken))
}

// EnsureRunning looks up the agent, decrypts its DB credentials, and starts
// (or reconnects to) the agent container. Returns the running container.
func (d *Dispatcher) EnsureRunning(ctx context.Context, agentID uuid.UUID) (*container.Container, error) {
	runtimeLock, err := d.db.AcquireAdvisoryLock(ctx, "agent-runtime:"+agentID.String())
	if err != nil {
		return nil, fmt.Errorf("lock agent runtime: %w", err)
	}
	defer runtimeLock.Unlock()

	// Hold the swap mutex for the whole GetAgent → StartAgent window so a
	// concurrent build's Phase F can't slip in between the agent read
	// and the StartAgent call, leaving us starting the OLD image while
	// the build proceeds to swap in the new one. Reading the agent
	// INSIDE the lock guarantees we always see the post-swap image_ref.
	unlockSwap := d.containers.LockSwap(agentID)
	defer unlockSwap()

	tx, err := d.db.Pool().Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin runtime start: %w", err)
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agent, err := q.GetAgentByIDForUpdate(ctx, toPgUUID(agentID))
	if err != nil {
		return nil, fmt.Errorf("get agent: %w", err)
	}
	if agent.ImageRef == "" {
		return nil, ErrAgentNoImage
	}
	// Stopped means the operator (or a failed rebuild) parked this agent
	// and doesn't want it auto-restarted. Any trigger path that hits this
	// gate while the agent is stopped must surface a clear error, not
	// silently bring it back up. Manual Start is the only way out.
	if agent.Status == "stopped" {
		return nil, ErrAgentStopped
	}
	if agent.JobDispatchPausedBuildID.Valid {
		build, err := q.GetAgentBuildForDeployment(ctx, dbq.GetAgentBuildForDeploymentParams{
			BuildID: agent.JobDispatchPausedBuildID, AgentID: agent.ID,
		})
		if err != nil {
			return nil, fmt.Errorf("get paused deployment: %w", err)
		}
		if build.DeploymentPhase == "starting" {
			return nil, ErrAgentDeploying
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit runtime selection: %w", err)
	}

	// Decrypt DB password from its dedicated column.
	dbPassword, err := d.encryptor.Get(ctx, "agent/"+agentID.String()+"/db_password", agent.DbPassword)
	if err != nil {
		return nil, fmt.Errorf("decrypt db password: %w", err)
	}

	// Build agent environment.
	schemaName := "agent_" + sanitizeUUID(agentID.String())
	agentDBURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?search_path=%s&sslmode=%s",
		schemaName, url.QueryEscape(dbPassword), d.cfg.DBHostAgent, d.cfg.DBPortAgent,
		d.cfg.DBName, schemaName, d.cfg.DBSSLMode)

	agentToken, err := auth.IssueAgentToken(d.cfg.JWTSecret, agentID, agent.AgentTokenVersion)
	if err != nil {
		return nil, fmt.Errorf("issue agent token: %w", err)
	}

	// On a cold start, create the role only if it is MISSING (e.g. a recreated
	// Postgres volume that lost it). Never ALTER an existing role here: ALTER
	// ROLE ... PASSWORD rewrites the scram-sha-256 verifier, and one landing
	// mid-handshake makes the agent's connect fail with a spurious 28P01 for
	// the correct password. Password drift is instead reconciled on the next
	// build (builder.ensureAgentRole), which runs before any container of the
	// agent starts, so it can't race a live connect. Gated on "not already
	// running" to skip the warm forward path. Best-effort.
	if running, _ := d.containers.GetRunning(ctx, agentID); running == nil {
		if !d.roleExists(ctx, schemaName) {
			if _, err := d.db.Pool().Exec(ctx, "SELECT create_agent_role($1, $2)", schemaName, dbPassword); err != nil {
				d.logger.Warn("create missing agent db role before cold start",
					zap.String("agent", agentID.String()), zap.Error(err))
			}
		}
	}

	c, err := d.containers.StartAgent(ctx, container.AgentOpts{
		AgentID: agentID,
		Image:   agent.ImageRef,
		Token:   agentToken,
		Env: map[string]string{
			"AIRLOCK_AGENT_ID": agentID.String(),
			"AIRLOCK_API_URL":  d.cfg.APIURLAgent,
			"AIRLOCK_DB_URL":   agentDBURL,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("start agent: %w", err)
	}
	return c, nil
}

// roleExists reports whether the agent's Postgres role is present. Used to
// create a role only when it's genuinely missing (recreated DB volume) without
// touching an existing one's password. On query error it returns true (assume
// present) so we never CREATE/ALTER on a transient hiccup.
func (d *Dispatcher) roleExists(ctx context.Context, roleName string) bool {
	var exists bool
	if err := d.db.Pool().QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", roleName).Scan(&exists); err != nil {
		d.logger.Warn("role-exists check failed; skipping create", zap.Error(err))
		return true
	}
	return exists
}

// ForwardWebhook ensures the agent is running, creates a run record, and POSTs
// the webhook payload to the agent container. Returns the response body stream
// and the run ID. The timeout parameter controls the HTTP client timeout.
func (d *Dispatcher) ForwardWebhook(ctx context.Context, agentID uuid.UUID, path string, body []byte, bridgeID *uuid.UUID, timeout time.Duration) (io.ReadCloser, uuid.UUID, error) {
	c, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	if bridgeID != nil {
		return nil, uuid.Nil, service.ErrInvalidInput
	}
	agent, err := dbq.New(d.db.Pool()).GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		return nil, uuid.Nil, err
	}
	input := json.RawMessage(body)
	if !json.Valid(input) {
		input, err = json.Marshal(string(body))
		if err != nil {
			return nil, uuid.Nil, err
		}
	}
	run, err := execution.New(d.db).AdmitApp(ctx, agentID, agent.AgentTokenVersion, execution.Webhook, path, input)
	if err != nil {
		return nil, uuid.Nil, err
	}
	runID := pgUUID(run.ID)

	rc, err := d.forward(ctx, agentID, c, "POST", "/webhook/"+path, body, runID, uuid.Nil, timeout)
	if err != nil {
		d.failRunDispatch(runID, err)
		return nil, uuid.Nil, err
	}
	return rc, runID, nil
}

// FailRouteRun terminalizes a route run when reverse proxying cannot establish
// or maintain the request to the agent runtime.
func (d *Dispatcher) FailRouteRun(runID uuid.UUID, err error) {
	d.failRunDispatch(runID, err)
}

// ForwardJob attaches a run to a leased attempt before synchronously invoking
// the exact registered handler version in the agent runtime.
func (d *Dispatcher) ForwardJob(ctx context.Context, job dbq.AgentJob, attempt dbq.AgentJobAttempt) (wire.JobRunResponse, uuid.UUID, error) {
	job, err := dbq.New(d.db.Pool()).GetAgentJobByID(ctx, job.ID)
	if err != nil {
		return wire.JobRunResponse{}, uuid.Nil, err
	}
	agentID := pgUUID(job.AgentID)
	c, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return wire.JobRunResponse{}, uuid.Nil, err
	}

	var scheduledAt *time.Time
	if job.ScheduledAt.Valid {
		value := job.ScheduledAt.Time.UTC()
		scheduledAt = &value
	}
	request := wire.JobRunRequest{
		ID:               pgUUID(job.ID).String(),
		Name:             job.HandlerName,
		Version:          job.HandlerVersion,
		InputSchemaHash:  job.InputSchemaHash,
		OutputSchemaHash: job.OutputSchemaHash,
		Attempt:          attempt.AttemptNumber,
		TimeoutMs:        job.TimeoutMs,
		Input:            job.InputPayload,
		ScheduledAt:      scheduledAt,
	}
	run, err := execution.New(d.db).AdmitJob(ctx, pgUUID(job.ID), attempt.AttemptNumber, pgUUID(attempt.LeaseToken))
	if err != nil {
		return wire.JobRunResponse{}, uuid.Nil, fmt.Errorf("create job run: %w", err)
	}
	runID := pgUUID(run.ID)

	deliveryCtx, cancel := context.WithCancel(ctx)
	d.registerInFlight(runID, cancel)
	defer cancel()
	defer d.deregisterInFlight(runID)
	stop := execution.Watch(deliveryCtx, dbq.New(d.db.Pool()), agentID, runID, cancel)
	defer stop()

	timeout := time.Duration(job.TimeoutMs)*time.Millisecond + 30*time.Second
	rc, err := d.forwardRequest(deliveryCtx, agentID, c, "POST", fmt.Sprintf("/job/%s/%d", job.HandlerName, job.HandlerVersion), nil, runID, uuid.Nil, timeout, &request)
	if err != nil {
		d.failRunDispatch(runID, err)
		return wire.JobRunResponse{}, runID, err
	}
	defer rc.Close()
	var result wire.JobRunResponse
	decoder := json.NewDecoder(io.LimitReader(rc, 128<<10))
	if err := decoder.Decode(&result); err != nil {
		d.failRunDispatch(runID, err)
		return wire.JobRunResponse{}, runID, fmt.Errorf("decode job response: %w", err)
	}
	if !validJobRunStatus(result.Status) {
		err := fmt.Errorf("invalid job response status %q", result.Status)
		d.failRunDispatch(runID, err)
		return wire.JobRunResponse{}, runID, err
	}
	return result, runID, nil
}

func validJobRunStatus(status string) bool {
	return status == "success" || status == "error" || status == "timeout" || status == "retry"
}

type PromptRuntime interface {
	Start(context.Context, authz.Principal, uuid.UUID, wire.PromptInput) (io.ReadCloser, uuid.UUID, error)
	Recover(context.Context) error
}

// SetPromptRuntime binds the hosted chat service during server construction.
func (d *Dispatcher) SetPromptRuntime(runtime PromptRuntime) {
	if runtime == nil || d.chat != nil {
		panic("dispatcher: hosted chat must be configured exactly once")
	}
	d.chat = runtime
}

func (d *Dispatcher) RecoverChat(ctx context.Context) error {
	if d.chat == nil {
		return errors.New("hosted chat runtime is required")
	}
	if err := d.chat.Recover(ctx); err != nil {
		return err
	}
	if manager, ok := d.containers.(interface{ ReapJSExecutors(context.Context) error }); ok {
		return manager.ReapJSExecutors(ctx)
	}
	return nil
}

// ForwardPrompt starts app-bound chat in the hosted runtime. App startup only
// synchronizes its manifest and makes registered capability handlers available.
func (d *Dispatcher) ForwardPrompt(ctx context.Context, p authz.Principal, agentID uuid.UUID, input wire.PromptInput) (io.ReadCloser, uuid.UUID, error) {
	if _, err := execution.Principal(ctx, dbq.New(d.db.Pool()), p); err != nil {
		return nil, uuid.Nil, err
	}
	_, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	if d.chat == nil {
		panic("dispatcher: hosted chat runtime is required")
	}
	return d.chat.Start(ctx, p, agentID, input)
}

func appendRuntimeLocale(input *wire.PromptInput, uiLocale string) {
	if input.ForceCompact {
		return
	}
	input.Instructions = localepkg.AppendReplyInstruction(input.Instructions, uiLocale)
}

// failRunDispatch terminalizes a run when forwarding fails before Airlock can
// obtain a response stream. The forwarding context is commonly cancelled on
// this path, so cleanup uses its own short-lived context. A concurrent agent
// completion cannot be overwritten through the query's running-state CAS.
func (d *Dispatcher) failRunDispatch(runID uuid.UUID, dispatchErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	q := dbq.New(d.db.Pool())
	rows, err := q.FailRunDispatch(ctx, dbq.FailRunDispatchParams{
		ID:           toPgUUID(runID),
		ErrorMessage: dispatchErr.Error(),
	})
	if err != nil {
		d.logger.Error("terminalize failed run dispatch",
			zap.String("run_id", runID.String()), zap.Error(err))
		return
	}
	if rows == 0 {
		return
	}
	if err := q.UpdateRunLLMStats(ctx, toPgUUID(runID)); err != nil {
		d.logger.Error("aggregate failed run dispatch llm stats",
			zap.String("run_id", runID.String()), zap.Error(err))
	}
}

// RefreshAgent triggers a synchronous re-sync on the agent container. Used
// after server-side state changes the cached system prompt depends on
// (typically MCP OAuth completion) so the running agent picks up new tools
// without a restart. If the container isn't running, returns nil — there's
// nothing to refresh; the agent will sync fresh on its next startup.
func (d *Dispatcher) RefreshAgent(ctx context.Context, agentID uuid.UUID) error {
	c, err := d.containers.GetRunning(ctx, agentID)
	if err != nil {
		return fmt.Errorf("look up agent container: %w", err)
	}
	if c == nil {
		return nil
	}
	c, err = d.EnsureRunning(ctx, agentID)
	if err != nil {
		return fmt.Errorf("refresh agent runtime: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/refresh", nil)
	if err != nil {
		return fmt.Errorf("create refresh request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	// Synchronous: the agent runs sync inside its handler and only returns
	// once a.systemPrompt + a.mcpSchemas are updated. Generous timeout
	// because the agent's sync round-trips back to Airlock and does MCP
	// tool discovery server-side.
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post refresh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("agent /refresh returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

// forward sends an HTTP request to the agent container and returns the response body.
//
// Identity headers are loaded from the admitted run, never from request input.
func (d *Dispatcher) forward(ctx context.Context, agentID uuid.UUID, c *container.Container, method, path string, body []byte, runID, ownerToken uuid.UUID, timeout time.Duration) (io.ReadCloser, error) {
	return d.forwardRequest(ctx, agentID, c, method, path, body, runID, ownerToken, timeout, nil)
}

func (d *Dispatcher) forwardRequest(ctx context.Context, agentID uuid.UUID, c *container.Container, method, path string, body []byte, runID, ownerToken uuid.UUID, timeout time.Duration, job *wire.JobRunRequest) (io.ReadCloser, error) {
	blocked, err := d.runtimeForwardGate(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("lock agent forward: %w", err)
	}
	if blocked {
		return nil, ErrAgentDeploying
	}
	q := dbq.New(d.db.Pool())
	expiresAt := time.Now().Add(timeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expiresAt) {
		expiresAt = deadline
	}
	runtime, err := execution.IssueInvocation(ctx, q, agentID, runID, ownerToken, expiresAt)
	if err != nil {
		return nil, err
	}
	handedOff := false
	stopInvocationClose := context.AfterFunc(ctx, func() {
		if err := execution.CloseInvocation(q, runtime.InvocationToken); err != nil {
			d.logger.Error("close cancelled delivery invocation", zap.Error(err))
		}
	})
	defer func() {
		if !handedOff {
			stopInvocationClose()
			if err := execution.CloseInvocation(q, runtime.InvocationToken); err != nil {
				d.logger.Error("close failed delivery invocation", zap.Error(err))
			}
		}
	}()
	callerHeader, err := wire.EncodeCallerHeader(runtime.Caller)
	if err != nil {
		return nil, err
	}
	if job != nil {
		if runtime.Job == nil {
			return nil, errors.New("job delivery requires an admitted attempt")
		}
		job.Caller, job.ConversationID = runtime.Caller, runtime.ConversationID
		body, err = json.Marshal(job)
		if err != nil {
			return nil, err
		}
	}
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Run-ID", runID.String())
	req.Header.Set(wire.InvocationTokenHeader, runtime.InvocationToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.CallerHeader, callerHeader)
	if runtime.BridgeID != "" {
		req.Header.Set("X-Bridge-ID", runtime.BridgeID)
	}
	if job != nil {
		req.Header.Set("X-Airlock-Job-Lease-Token", runtime.Job.LeaseToken)
	}

	// Hold the container busy for the whole life of this request so the
	// idle reaper cannot stop it mid-run. MarkIdle fires on every exit
	// path: a transport error, a 4xx/5xx, or the streamed body's Close.
	client := &http.Client{Timeout: timeout}
	d.containers.MarkBusy(agentID)
	resp, err := client.Do(req)
	if err != nil {
		d.containers.MarkIdle(agentID)
		return nil, fmt.Errorf("forward to agent: %w", err)
	}
	if resp.StatusCode >= 400 {
		d.containers.MarkIdle(agentID)
		defer resp.Body.Close()
		return nil, fmt.Errorf("agent returned %d", resp.StatusCode)
	}
	handedOff = true
	return &busyCloser{ReadCloser: resp.Body, containers: d.containers, agentID: agentID, queries: q, invocationToken: runtime.InvocationToken, stopInvocationClose: stopInvocationClose}, nil
}

// --- helpers ---

func toPgUUID(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: u, Valid: true}
}

func pgUUID(u pgtype.UUID) uuid.UUID {
	return uuid.UUID(u.Bytes)
}

// sanitizeUUID removes hyphens from a UUID string for use as a schema name.
func sanitizeUUID(id string) string {
	return strings.ReplaceAll(id, "-", "")
}
