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

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
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
// (409 on HTTP, an in-chat notice on bridges, a JSON-RPC error on A2A)
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

	// In-flight per-run state registry. Populated when prompt, A2A, and job
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
//
// A2A cascade: the cancel also walks runs.parent_run_id downward and
// fires the cancel hook on every still-in-flight descendant. The HTTP
// disconnect chain already cascades cancels (parent's outbound HTTP
// closing → child's ctx.Done() → child's CancelRun), but this gives an
// explicit best-effort kick for runs on the same replica when the user
// cancels mid-chain.
func (d *Dispatcher) CancelRun(runID uuid.UUID) bool {
	d.mu.Lock()
	state, ok := d.inFlight[runID]
	delete(d.inFlight, runID)
	d.mu.Unlock()
	if ok {
		state.cancel()
	}
	d.cancelDescendants(context.Background(), runID)
	return ok
}

// cancelDescendants fires cancel on every descendant run reachable from
// rootRunID via parent_run_id. Best-effort: descendants on a different
// replica won't have an in-flight entry here and will only cancel when
// their parent's HTTP request closes from above. Cross-replica
// propagation is the same pre-existing gap CancelRun already has.
//
// Safe to call when the dispatcher has no DB (some unit tests construct
// a bare Dispatcher with only the inFlight registry); skip the
// descendant walk in that case.
func (d *Dispatcher) cancelDescendants(ctx context.Context, rootRunID uuid.UUID) {
	if d.db == nil {
		return
	}
	q := dbq.New(d.db.Pool())
	rows, err := q.GetDescendantRuns(ctx, toPgUUID(rootRunID))
	if err != nil {
		d.logger.Warn("cancelDescendants: lookup failed",
			zap.String("root_run_id", rootRunID.String()), zap.Error(err))
		return
	}
	for _, r := range rows {
		childID := pgUUID(r.ID)
		d.mu.Lock()
		state, ok := d.inFlight[childID]
		delete(d.inFlight, childID)
		d.mu.Unlock()
		if ok {
			state.cancel()
		}
	}
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
	containers container.ContainerManager
	agentID    uuid.UUID
}

func (b *busyCloser) Close() error {
	b.containers.MarkIdle(b.agentID)
	return b.ReadCloser.Close()
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

	runID, err := d.createRun(ctx, agentID, bridgeID, nil, nil, agentsdk.AccessPublic, body, "webhook", path)
	if err != nil {
		return nil, uuid.Nil, err
	}

	rc, err := d.forward(ctx, agentID, c, "POST", "/webhook/"+path, body, runID, bridgeID, nil, nil, timeout)
	if err != nil {
		d.failRunDispatch(runID, err)
		return nil, uuid.Nil, err
	}
	return rc, runID, nil
}

// CreateRouteRun records trusted subdomain ingress after route authorization
// has selected the effective user and access level.
func (d *Dispatcher) CreateRouteRun(ctx context.Context, agentID uuid.UUID, userID *uuid.UUID, callerAccess agentsdk.Access, input []byte, routeRef string) (uuid.UUID, error) {
	return d.createRun(ctx, agentID, nil, nil, userID, callerAccess, input, "route", routeRef)
}

// FailRouteRun terminalizes a route run when reverse proxying cannot establish
// or maintain the request to the agent runtime.
func (d *Dispatcher) FailRouteRun(runID uuid.UUID, err error) {
	d.failRunDispatch(runID, err)
}

// ForwardJob attaches a run to a leased attempt before synchronously invoking
// the exact registered handler version in the agent runtime.
func (d *Dispatcher) ForwardJob(ctx context.Context, job dbq.AgentJob, attempt dbq.AgentJobAttempt) (wire.JobRunResponse, uuid.UUID, error) {
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
		ID:                      pgUUID(job.ID).String(),
		Name:                    job.HandlerName,
		Version:                 job.HandlerVersion,
		InputSchemaHash:         job.InputSchemaHash,
		OutputSchemaHash:        job.OutputSchemaHash,
		Attempt:                 attempt.AttemptNumber,
		TimeoutMs:               job.TimeoutMs,
		Input:                   job.InputPayload,
		ScheduledAt:             scheduledAt,
		InitiatorKind:           job.InitiatorKind,
		InitiatorUserID:         optionalUUID(job.InitiatorUserID),
		InitiatorConversationID: optionalUUID(job.InitiatorConversationID),
		CallerAccess:            wire.Access(job.InitiatorAccess),
	}
	body, err := json.Marshal(request)
	if err != nil {
		return wire.JobRunResponse{}, uuid.Nil, fmt.Errorf("marshal job delivery: %w", err)
	}

	tx, err := d.db.Pool().Begin(ctx)
	if err != nil {
		return wire.JobRunResponse{}, uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agent, err := q.GetAgentByID(ctx, job.AgentID)
	if err != nil {
		return wire.JobRunResponse{}, uuid.Nil, fmt.Errorf("load agent for job run: %w", err)
	}
	if agent.AgentTokenVersion != attempt.RuntimeGeneration {
		return wire.JobRunResponse{}, uuid.Nil, fmt.Errorf("job runtime generation changed from %d to %d", attempt.RuntimeGeneration, agent.AgentTokenVersion)
	}
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID:              job.AgentID,
		InputPayload:         job.InputPayload,
		SourceRef:            agent.SourceRef,
		TriggerType:          "job",
		TriggerRef:           pgUUID(job.ID).String(),
		CallerUserID:         job.InitiatorUserID,
		CallerConversationID: job.InitiatorConversationID,
		CallerAccess:         job.InitiatorAccess,
	})
	if err != nil {
		return wire.JobRunResponse{}, uuid.Nil, fmt.Errorf("create job run: %w", err)
	}
	runID := pgUUID(run.ID)
	started, err := q.StartAgentJobAttempt(ctx, dbq.StartAgentJobAttemptParams{
		RunID: run.ID, JobID: job.ID, AttemptNumber: attempt.AttemptNumber,
		LeaseOwner: attempt.LeaseOwner, LeaseToken: attempt.LeaseToken,
	})
	if err != nil {
		return wire.JobRunResponse{}, uuid.Nil, fmt.Errorf("attach job run: %w", err)
	}
	if started == 0 {
		return wire.JobRunResponse{}, uuid.Nil, ErrJobLeaseLost
	}
	if err := tx.Commit(ctx); err != nil {
		return wire.JobRunResponse{}, uuid.Nil, err
	}

	deliveryCtx, cancel := context.WithCancel(ctx)
	d.registerInFlight(runID, cancel)
	defer cancel()
	defer d.deregisterInFlight(runID)

	timeout := time.Duration(job.TimeoutMs)*time.Millisecond + 30*time.Second
	headers := make(http.Header)
	headers.Set("X-Airlock-Job-Lease-Token", pgUUID(attempt.LeaseToken).String())
	rc, err := d.forwardWithHeaders(deliveryCtx, agentID, c, "POST", fmt.Sprintf("/job/%s/%d", job.HandlerName, job.HandlerVersion), body, runID, nil, nil, nil, timeout, headers)
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

// ForwardPrompt ensures the agent is running, creates a run record, and POSTs
// the prompt input to the agent container. Returns the response body stream
// (NDJSON) and the run ID. userID is the prompting user (anchor for A2A
// VisibleSiblings); pass nil for anonymous/system runs.
func (d *Dispatcher) ForwardPrompt(ctx context.Context, agentID uuid.UUID, input wire.PromptInput, bridgeID *uuid.UUID, userID *uuid.UUID) (io.ReadCloser, uuid.UUID, error) {
	c, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	// Populate VisibleSiblings: every sibling the user could call directly
	// via MCP. The LLM's prompt and the VM bindings render against the
	// same set so the model never sees a binding it can't actually invoke.
	visible, err := d.computeVisibleSiblings(ctx, agentID, userID)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("compute visible siblings: %w", err)
	}
	input.VisibleSiblings = visible

	// Per-turn <env> context: state the channel explicitly (web or the
	// bridge's platform), and resolve the originating user. Fail-soft.
	input.Platform = d.resolvePlatform(ctx, bridgeID)
	input.UserDisplayName, input.UserEmail = d.resolveUserEnv(ctx, userID)

	d.stampSyncHash(ctx, agentID, &input)

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("marshal prompt input: %w", err)
	}

	runID, err := d.createRun(ctx, agentID, bridgeID, nil, userID, agentsdk.Access(input.CallerAccess), payload, "prompt", input.ConversationID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	// Register a cancel hook so DELETE /api/v1/runs/{runID} can abort the
	// outbound request: cancel() trips the agent-side r.Context(),
	// vm.Interrupt fires, and the agent finalizes via /run/complete.
	// PromptHTTPCeiling caps absolute wall time on the HTTP client.
	cancelCtx, cancel := context.WithCancel(ctx)
	d.registerInFlight(runID, cancel)

	rc, err := d.forward(cancelCtx, agentID, c, "POST", "/prompt", payload, runID, bridgeID, nil, userID, PromptHTTPCeiling)
	if err != nil {
		d.deregisterInFlight(runID)
		cancel()
		d.failRunDispatch(runID, err)
		return nil, uuid.Nil, err
	}
	return &runBodyCloser{ReadCloser: rc, dispatcher: d, runID: runID, cancel: cancel}, runID, nil
}

// ForwardA2APrompt is ForwardPrompt for the sibling-agent code path:
// the caller is another agent's run, parentRunID is its run.id, and the
// new run's parent_run_id and trigger_type/_ref are wired accordingly.
// callerAccess is the access level Airlock pre-resolved against the
// target agent (see api/access.computeA2ACallerAccess). userID is the
// original user (the human at the top of the chain — propagated through
// every A2A hop via the conversation's user_id), used for both the new
// run's VisibleSiblings computation and audit.
func (d *Dispatcher) ForwardA2APrompt(ctx context.Context, agentID uuid.UUID, parentRunID uuid.UUID, callerAccess agentsdk.Access, userID *uuid.UUID, input wire.PromptInput) (io.ReadCloser, uuid.UUID, error) {
	c, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	visible, err := d.computeVisibleSiblings(ctx, agentID, userID)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("compute visible siblings: %w", err)
	}
	input.VisibleSiblings = visible
	input.CallerAccess = wire.Access(callerAccess)
	input.DirectTools = callerAccess == agentsdk.AccessPublic

	// A2A runs deliver to the calling agent, not a human channel.
	input.Platform = "a2a"
	input.UserDisplayName, input.UserEmail = d.resolveUserEnv(ctx, userID)

	d.stampSyncHash(ctx, agentID, &input)

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("marshal prompt input: %w", err)
	}

	// Anon and user MCP callers reach this path with parentRunID = uuid.Nil
	// — they aren't a sibling A2A child, just an external prompt that
	// happens to enter via the MCP endpoint. Translate Nil → nil so we
	// insert NULL parent_run_id (instead of an all-zero FK that trips
	// runs_parent_run_id_fkey). trigger_type stays "a2a" so analytics
	// can still distinguish these from web /prompt runs. trigger_ref is
	// the conversation this turn runs in (resolved/minted by the MCP
	// handler) — same convention as prompt runs, so contextId round-trips
	// and parent-conversation lookups resolve correctly. The caller is
	// linked via parent_run_id, not trigger_ref.
	var parentRunIDPtr *uuid.UUID
	if parentRunID != uuid.Nil {
		parentRunIDPtr = &parentRunID
	}
	runID, err := d.createRun(ctx, agentID, nil, parentRunIDPtr, userID, callerAccess, payload, "a2a", input.ConversationID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	d.registerInFlight(runID, cancel)

	rc, err := d.forward(cancelCtx, agentID, c, "POST", "/prompt", payload, runID, nil, parentRunIDPtr, userID, PromptHTTPCeiling)
	if err != nil {
		d.deregisterInFlight(runID)
		cancel()
		d.failRunDispatch(runID, err)
		return nil, uuid.Nil, err
	}
	return &runBodyCloser{ReadCloser: rc, dispatcher: d, runID: runID, cancel: cancel}, runID, nil
}

// stampSyncHash sets input.ExpectedSyncHash to the agent's current config
// fingerprint so the agent can detect a stale sync cache and self-heal (see
// AgentConfigHash). Best-effort: a lookup failure leaves the field empty, which
// the agent reads as "no check" — it never blocks or fails the dispatch.
func (d *Dispatcher) stampSyncHash(ctx context.Context, agentID uuid.UUID, input *wire.PromptInput) {
	ag, err := dbq.New(d.db.Pool()).GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		d.logger.Warn("stamp sync hash: load agent",
			zap.String("agent_id", agentID.String()), zap.Error(err))
		return
	}
	input.ExpectedSyncHash = AgentConfigHash(ag)
}

// computeVisibleSiblings returns the set of agent IDs this run's user is
// permitted to A2A-call from the prompting agent: the parent's siblings on
// which the driving user holds a grant (resolved through the user's full
// grantee-set, so group grants incl. All-Users count). Anonymous /
// cron / webhook runs (userID == nil) pass an empty grantee-set and get
// nothing — they can't A2A in v1, and a non-member has no grant anyway.
func (d *Dispatcher) computeVisibleSiblings(ctx context.Context, agentID uuid.UUID, userID *uuid.UUID) ([]uuid.UUID, error) {
	q := dbq.New(d.db.Pool())
	var grantees []pgtype.UUID
	if userID != nil {
		var role auth.Role
		if u, err := q.GetUserByID(ctx, toPgUUID(*userID)); err == nil {
			role = auth.Role(u.TenantRole)
		}
		for _, id := range authz.UserPrincipal(*userID, role).GranteeSet() {
			grantees = append(grantees, toPgUUID(id))
		}
	}
	rows, err := q.ListVisibleSiblings(ctx, dbq.ListVisibleSiblingsParams{
		ParentAgentID: toPgUUID(agentID),
		GranteeIds:    grantees,
	})
	if err != nil {
		return nil, err
	}
	out := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		out = append(out, pgUUID(r))
	}
	return out, nil
}

// createRun inserts a new run record and returns its ID.
func (d *Dispatcher) createRun(ctx context.Context, agentID uuid.UUID, bridgeID, parentRunID, userID *uuid.UUID, callerAccess agentsdk.Access, inputPayload []byte, triggerType, triggerRef string) (uuid.UUID, error) {
	q := dbq.New(d.db.Pool())

	var pgBridgeID pgtype.UUID
	if bridgeID != nil {
		pgBridgeID = toPgUUID(*bridgeID)
	}
	var pgParentRunID pgtype.UUID
	if parentRunID != nil {
		pgParentRunID = toPgUUID(*parentRunID)
	}
	var pgUserID pgtype.UUID
	if userID != nil {
		pgUserID = toPgUUID(*userID)
	}
	var pgConversationID pgtype.UUID
	if triggerType == "prompt" || triggerType == "a2a" {
		conversationID, err := uuid.Parse(triggerRef)
		if err != nil {
			return uuid.Nil, fmt.Errorf("parse run conversation: %w", err)
		}
		pgConversationID = toPgUUID(conversationID)
	}
	if callerAccess == "" {
		callerAccess = agentsdk.AccessPublic
	}
	if inputPayload == nil {
		inputPayload = []byte("{}")
	}

	// Snapshot the agent's current source_ref so we know which version ran.
	var sourceRef string
	if agent, err := q.GetAgentByID(ctx, toPgUUID(agentID)); err == nil {
		sourceRef = agent.SourceRef
	}

	run, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID:              toPgUUID(agentID),
		BridgeID:             pgBridgeID,
		ParentRunID:          pgParentRunID,
		InputPayload:         inputPayload,
		SourceRef:            sourceRef,
		TriggerType:          triggerType,
		TriggerRef:           triggerRef,
		CallerUserID:         pgUserID,
		CallerConversationID: pgConversationID,
		CallerAccess:         string(callerAccess),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("create run: %w", err)
	}
	return pgUUID(run.ID), nil
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
// parentRunID, when non-nil, becomes the X-Parent-Run-ID header so the
// callee's agentsdk can scope reads on __incoming/run-<parent>/ paths
// to this specific A2A call. userID, when non-nil, becomes X-User-ID
// — the originating user, used by the callee for ScopeUser-scoped
// directories. Both are nil for the web / bridge / cron / webhook
// flows that pre-existed scoping (those handlers pass principal via
// PromptInput / conversation lookups).
func (d *Dispatcher) forward(ctx context.Context, agentID uuid.UUID, c *container.Container, method, path string, body []byte, runID uuid.UUID, bridgeID, parentRunID, userID *uuid.UUID, timeout time.Duration) (io.ReadCloser, error) {
	return d.forwardWithHeaders(ctx, agentID, c, method, path, body, runID, bridgeID, parentRunID, userID, timeout, nil)
}

func (d *Dispatcher) forwardWithHeaders(ctx context.Context, agentID uuid.UUID, c *container.Container, method, path string, body []byte, runID uuid.UUID, bridgeID, parentRunID, userID *uuid.UUID, timeout time.Duration, headers http.Header) (io.ReadCloser, error) {
	blocked, err := d.runtimeForwardGate(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("lock agent forward: %w", err)
	}
	if blocked {
		return nil, ErrAgentDeploying
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
	req.Header.Set("Content-Type", "application/json")
	if bridgeID != nil {
		req.Header.Set("X-Bridge-ID", bridgeID.String())
	}
	if parentRunID != nil && *parentRunID != uuid.Nil {
		req.Header.Set("X-Parent-Run-ID", parentRunID.String())
	}
	if userID != nil && *userID != uuid.Nil {
		req.Header.Set("X-User-ID", userID.String())
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
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
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("agent returned %d: %s", resp.StatusCode, respBody)
	}
	return &busyCloser{ReadCloser: resp.Body, containers: d.containers, agentID: agentID}, nil
}

func optionalUUID(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return pgUUID(id).String()
}

// --- helpers ---

// resolvePlatform returns the channel name for the <env> block: "web" when
// there's no bridge, else the bridge's platform type (telegram).
// Fail-soft — a lookup miss logs and returns "" (the line is then omitted)
// rather than guessing.
func (d *Dispatcher) resolvePlatform(ctx context.Context, bridgeID *uuid.UUID) string {
	if bridgeID == nil {
		return "web"
	}
	q := dbq.New(d.db.Pool())
	b, err := q.GetBridgeByID(ctx, toPgUUID(*bridgeID))
	if err != nil {
		d.logger.Warn("env: resolve bridge platform failed", zap.String("bridge_id", bridgeID.String()), zap.Error(err))
		return ""
	}
	return b.Type
}

// resolveUserEnv returns the originating user's display name + email for the
// <env> block. Fail-soft — no user, or a lookup miss, yields empty strings
// (the User line is then omitted).
func (d *Dispatcher) resolveUserEnv(ctx context.Context, userID *uuid.UUID) (name, email string) {
	if userID == nil || *userID == uuid.Nil {
		return "", ""
	}
	q := dbq.New(d.db.Pool())
	u, err := q.GetUserByID(ctx, toPgUUID(*userID))
	if err != nil {
		d.logger.Warn("env: resolve user failed", zap.String("user_id", userID.String()), zap.Error(err))
		return "", ""
	}
	return u.DisplayName, u.Email
}

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
