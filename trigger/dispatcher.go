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
// webhook callers pass their own (typically shorter) timeout to
// ForwardFire/Webhook.
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
	ErrAgentNoImage = errors.New("agent has no image")
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

// runState tracks an in-flight run for cancellation. Cron, webhook, and
// prompt runs all register their cancel func here so DELETE /runs/{id}
// can abort them.
type runState struct {
	cancel context.CancelFunc
}

// Dispatcher ensures agent containers are running and forwards HTTP requests to them.
type Dispatcher struct {
	cfg        *config.Config
	db         *db.DB
	containers container.ContainerManager
	encryptor  secrets.Store
	logger     *zap.Logger

	// In-flight per-run state registry. Populated when ForwardPrompt /
	// ForwardFire / ForwardWebhook starts streaming from the agent,
	// removed when the response body is closed (after publishRunEvents
	// drains it). CancelRun(runID) fires the registered cancel func,
	// which aborts the outbound HTTP request — the agent's r.Context()
	// then cancels, vm.Interrupt fires, and the agent finalizes via its
	// detached /api/agent/run/complete POST.
	mu       sync.Mutex
	inFlight map[uuid.UUID]*runState
}

// NewDispatcher creates a Dispatcher.
func NewDispatcher(cfg *config.Config, db *db.DB, containers container.ContainerManager, enc secrets.Store, logger *zap.Logger) *Dispatcher {
	return &Dispatcher{
		cfg:        cfg,
		db:         db,
		containers: containers,
		encryptor:  enc,
		logger:     logger,
		inFlight:   make(map[uuid.UUID]*runState),
	}
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

// runBodyCloser wraps the agent's response body so closing it deregisters
// the run from the cancel registry. Without this the registry would leak
// entries for runs that finished naturally (no CancelRun call).
type runBodyCloser struct {
	io.ReadCloser
	dispatcher *Dispatcher
	runID      uuid.UUID
}

func (r *runBodyCloser) Close() error {
	r.dispatcher.deregisterInFlight(r.runID)
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
	// Hold the swap mutex for the whole GetAgent → StartAgent window so a
	// concurrent build's Phase F can't slip in between the agent read
	// and the StartAgent call, leaving us starting the OLD image while
	// the build proceeds to swap in the new one. Reading the agent
	// INSIDE the lock guarantees we always see the post-swap image_ref.
	unlockSwap := d.containers.LockSwap(agentID)
	defer unlockSwap()

	q := dbq.New(d.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
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
		return nil, uuid.Nil, err
	}
	return rc, runID, nil
}

// ForwardFire creates one run attempt and returns the handler's typed
// acknowledgement after /fire/{slug} completes.
func (d *Dispatcher) ForwardFire(ctx context.Context, agentID uuid.UUID, event wire.ScheduleFireRequest, timeout time.Duration) (wire.ScheduleFireResponse, uuid.UUID, error) {
	c, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return wire.ScheduleFireResponse{}, uuid.Nil, err
	}
	body, err := json.Marshal(event)
	if err != nil {
		return wire.ScheduleFireResponse{}, uuid.Nil, fmt.Errorf("marshal schedule event: %w", err)
	}

	runID, err := d.createRun(ctx, agentID, nil, nil, nil, agentsdk.AccessPublic, body, "schedule", event.Slug)
	if err != nil {
		return wire.ScheduleFireResponse{}, uuid.Nil, err
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	d.registerInFlight(runID, cancel)

	rc, err := d.forward(cancelCtx, agentID, c, "POST", "/fire/"+event.Slug, body, runID, nil, nil, nil, timeout)
	if err != nil {
		d.deregisterInFlight(runID)
		cancel()
		return wire.ScheduleFireResponse{}, runID, err
	}
	defer cancel()
	defer d.deregisterInFlight(runID)
	defer rc.Close()
	var result wire.ScheduleFireResponse
	decoder := json.NewDecoder(io.LimitReader(rc, 64<<10))
	if err := decoder.Decode(&result); err != nil {
		return wire.ScheduleFireResponse{}, runID, fmt.Errorf("decode schedule response: %w", err)
	}
	if result.Status != "success" && result.Status != "error" && result.Status != "timeout" {
		return wire.ScheduleFireResponse{}, runID, fmt.Errorf("invalid schedule response status %q", result.Status)
	}
	return result, runID, nil
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
		return nil, uuid.Nil, err
	}
	return &runBodyCloser{ReadCloser: rc, dispatcher: d, runID: runID}, runID, nil
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
		return nil, uuid.Nil, err
	}
	return &runBodyCloser{ReadCloser: rc, dispatcher: d, runID: runID}, runID, nil
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
