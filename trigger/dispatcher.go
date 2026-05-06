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
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Prompt-run timeout shape:
//
//   - PromptBaseDuration: deadline armed when ForwardPrompt registers the
//     run. A timer fires cancel() at this point unless extended.
//   - ExtendIncrement / MaxExtensions: ExtendRun adds Increment to the
//     deadline up to MaxExtensions times. 2 + 5×5 = 27 min absolute cap.
//   - PromptHTTPCeiling: the http.Client.Timeout on the outbound request.
//     Has to clear MaxExtensions×ExtendIncrement + base + grace, otherwise
//     the client kills the connection before the deadline timer fires.
//
// Cron and webhook callers pass their own timeout to ForwardCron/Webhook;
// they don't get the timer-driven extension treatment because no user is
// watching to click Extend.
const (
	PromptBaseDuration = 2 * time.Minute
	ExtendIncrement    = 5 * time.Minute
	MaxExtensions      = 5
	PromptHTTPCeiling  = 35 * time.Minute
)

// ErrRunNotInFlight is returned by ExtendRun when no live run matches the
// given ID — finished, never started, or already cancelled.
var ErrRunNotInFlight = errors.New("run not in flight")

// ErrExtensionCeiling is returned by ExtendRun when the run has already
// been extended MaxExtensions times.
var ErrExtensionCeiling = errors.New("max extensions reached")

// runState tracks an in-flight run: its cancel func plus an optional
// deadline timer for extendable (prompt) runs. Cron/webhook runs register
// with timer == nil and are cancellable but not extendable.
type runState struct {
	cancel context.CancelFunc

	// timer fires cancel() at deadline. nil for non-extendable runs.
	timer *time.Timer

	// mu guards deadline + extends; held during ExtendRun's timer.Reset
	// to keep the in-memory deadline consistent with the scheduled fire.
	mu       sync.Mutex
	deadline time.Time
	extends  int
}

// Dispatcher ensures agent containers are running and forwards HTTP requests to them.
type Dispatcher struct {
	cfg        *config.Config
	db         *db.DB
	containers container.ContainerManager
	encryptor  secrets.Store
	logger     *zap.Logger

	// In-flight per-run state registry. Populated when ForwardPrompt /
	// ForwardCron starts streaming from the agent, removed when the
	// response body is closed (after publishRunEvents drains it).
	// CancelRun(runID) fires the registered cancel func, which aborts
	// the outbound HTTP request — the agent's r.Context() then cancels,
	// vm.Interrupt fires, and the agent finalizes via its detached
	// /api/agent/run/complete POST. ExtendRun(runID) pushes the deadline
	// timer for extendable (prompt) runs.
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
func (d *Dispatcher) CancelRun(runID uuid.UUID) bool {
	d.mu.Lock()
	state, ok := d.inFlight[runID]
	delete(d.inFlight, runID)
	d.mu.Unlock()
	if ok {
		if state.timer != nil {
			state.timer.Stop()
		}
		state.cancel()
	}
	return ok
}

// ExtendRun pushes the deadline of an extendable in-flight run by `by`.
// Returns the new deadline and the number of extensions still available.
// Errors with ErrRunNotInFlight if the run finished/cancelled (or is a
// non-extendable cron/webhook run), or ErrExtensionCeiling if the run has
// already been extended MaxExtensions times.
func (d *Dispatcher) ExtendRun(runID uuid.UUID, by time.Duration) (time.Time, int, error) {
	d.mu.Lock()
	state, ok := d.inFlight[runID]
	d.mu.Unlock()
	if !ok || state.timer == nil {
		return time.Time{}, 0, ErrRunNotInFlight
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.extends >= MaxExtensions {
		return state.deadline, 0, ErrExtensionCeiling
	}
	// Stop returns false if the timer has already fired (cancel is already
	// running, request is dying). Treat that as "not in flight" — ignoring
	// the race window, the user would shortly see the bubble flip cancelled.
	if !state.timer.Stop() {
		return time.Time{}, 0, ErrRunNotInFlight
	}
	state.extends++
	state.deadline = state.deadline.Add(by)
	state.timer.Reset(time.Until(state.deadline))
	return state.deadline, MaxExtensions - state.extends, nil
}

// InFlightIDs returns a snapshot of currently-tracked run IDs. Used by the
// stuck-run sweeper so it doesn't race the dispatcher and prematurely
// terminate a long (extended) run that's still alive in memory.
func (d *Dispatcher) InFlightIDs() []uuid.UUID {
	d.mu.Lock()
	defer d.mu.Unlock()
	ids := make([]uuid.UUID, 0, len(d.inFlight))
	for id := range d.inFlight {
		ids = append(ids, id)
	}
	return ids
}

// registerInFlight stores cancel + (optional) deadline timer for a run.
// Pass extendable=true for prompt runs (user can click Extend); false for
// cron/webhook runs that just need the cancel hook for CancelRun.
func (d *Dispatcher) registerInFlight(runID uuid.UUID, cancel context.CancelFunc, extendable bool) {
	state := &runState{cancel: cancel}
	if extendable {
		state.deadline = time.Now().Add(PromptBaseDuration)
		state.timer = time.AfterFunc(PromptBaseDuration, cancel)
	}
	d.mu.Lock()
	d.inFlight[runID] = state
	d.mu.Unlock()
}

func (d *Dispatcher) deregisterInFlight(runID uuid.UUID) {
	d.mu.Lock()
	state, ok := d.inFlight[runID]
	delete(d.inFlight, runID)
	d.mu.Unlock()
	if ok && state.timer != nil {
		// Drop the deadline timer once the response body closes naturally.
		// Without this the timer would still fire well after the request
		// completed — harmless (cancel on a done ctx is a no-op) but a
		// pointless background goroutine until then.
		state.timer.Stop()
	}
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

// EnsureRunning looks up the agent, decrypts its DB credentials, and starts
// (or reconnects to) the agent container. Returns the running container.
func (d *Dispatcher) EnsureRunning(ctx context.Context, agentID uuid.UUID) (*container.Container, error) {
	q := dbq.New(d.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		return nil, fmt.Errorf("get agent: %w", err)
	}
	if agent.ImageRef == "" {
		return nil, errors.New("agent has no image")
	}

	// Decrypt DB password from its dedicated column.
	dbPassword, err := d.encryptor.Get(ctx, "agent/"+agentID.String()+"/db_password", agent.DbPassword)
	if err != nil {
		return nil, fmt.Errorf("decrypt db password: %w", err)
	}

	// Build agent environment.
	schemaName := "agent_" + sanitizeUUID(agentID.String())
	agentDBURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?search_path=%s&sslmode=%s",
		schemaName, url.QueryEscape(dbPassword), d.cfg.DBHostAgent, d.cfg.DBPort,
		d.cfg.DBName, schemaName, d.cfg.DBSSLMode)

	agentToken, err := auth.IssueAgentToken(d.cfg.JWTSecret, agentID)
	if err != nil {
		return nil, fmt.Errorf("issue agent token: %w", err)
	}

	c, err := d.containers.StartAgent(ctx, container.AgentOpts{
		AgentID: agentID,
		Image:   agent.ImageRef,
		Env: map[string]string{
			"AIRLOCK_AGENT_ID":    agentID.String(),
			"AIRLOCK_API_URL":     d.cfg.APIURLAgent,
			"AIRLOCK_DB_URL":      agentDBURL,
			"AIRLOCK_AGENT_TOKEN": agentToken,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("start agent: %w", err)
	}
	return c, nil
}

// ForwardWebhook ensures the agent is running, creates a run record, and POSTs
// the webhook payload to the agent container. Returns the response body stream
// and the run ID. The timeout parameter controls the HTTP client timeout.
func (d *Dispatcher) ForwardWebhook(ctx context.Context, agentID uuid.UUID, path string, body []byte, bridgeID *uuid.UUID, timeout time.Duration) (io.ReadCloser, uuid.UUID, error) {
	c, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	runID, err := d.createRun(ctx, agentID, bridgeID, body, "webhook", path)
	if err != nil {
		return nil, uuid.Nil, err
	}

	rc, err := d.forward(ctx, c, "POST", "/webhook/"+path, body, runID, bridgeID, timeout)
	if err != nil {
		return nil, uuid.Nil, err
	}
	return rc, runID, nil
}

// ForwardCron ensures the agent is running, creates a run record, and POSTs
// to the agent's cron endpoint. Returns the response body stream and the run ID.
// The timeout parameter controls the HTTP client timeout.
func (d *Dispatcher) ForwardCron(ctx context.Context, agentID uuid.UUID, cronName string, timeout time.Duration) (io.ReadCloser, uuid.UUID, error) {
	c, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	runID, err := d.createRun(ctx, agentID, nil, nil, "cron", cronName)
	if err != nil {
		return nil, uuid.Nil, err
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	d.registerInFlight(runID, cancel, false)

	rc, err := d.forward(cancelCtx, c, "POST", "/cron/"+cronName, nil, runID, nil, timeout)
	if err != nil {
		d.deregisterInFlight(runID)
		cancel()
		return nil, uuid.Nil, err
	}
	return &runBodyCloser{ReadCloser: rc, dispatcher: d, runID: runID}, runID, nil
}

// ForwardPrompt ensures the agent is running, creates a run record, and POSTs
// the prompt input to the agent container. Returns the response body stream
// (NDJSON) and the run ID.
func (d *Dispatcher) ForwardPrompt(ctx context.Context, agentID uuid.UUID, input agentsdk.PromptInput, bridgeID *uuid.UUID) (io.ReadCloser, uuid.UUID, error) {
	c, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("marshal prompt input: %w", err)
	}

	runID, err := d.createRun(ctx, agentID, bridgeID, payload, "prompt", input.ConversationID)
	if err != nil {
		return nil, uuid.Nil, err
	}

	// Register a cancel hook + deadline timer for this run before issuing
	// the outbound request. The timer fires cancel() at PromptBaseDuration
	// unless ExtendRun pushes it. CancelRun(runID) fires the cancel
	// directly; the streaming response body returns EOF and
	// publishRunEvents exits its read loop. The HTTP client timeout is set
	// to the absolute extension ceiling so the client doesn't kill the
	// connection before the timer-driven deadline does.
	cancelCtx, cancel := context.WithCancel(ctx)
	d.registerInFlight(runID, cancel, true)

	rc, err := d.forward(cancelCtx, c, "POST", "/prompt", payload, runID, bridgeID, PromptHTTPCeiling)
	if err != nil {
		d.deregisterInFlight(runID)
		cancel()
		return nil, uuid.Nil, err
	}
	return &runBodyCloser{ReadCloser: rc, dispatcher: d, runID: runID}, runID, nil
}

// createRun inserts a new run record and returns its ID.
func (d *Dispatcher) createRun(ctx context.Context, agentID uuid.UUID, bridgeID *uuid.UUID, inputPayload []byte, triggerType, triggerRef string) (uuid.UUID, error) {
	q := dbq.New(d.db.Pool())

	var pgBridgeID pgtype.UUID
	if bridgeID != nil {
		pgBridgeID = toPgUUID(*bridgeID)
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
		AgentID:      toPgUUID(agentID),
		BridgeID:     pgBridgeID,
		InputPayload: inputPayload,
		SourceRef:    sourceRef,
		TriggerType:  triggerType,
		TriggerRef:   triggerRef,
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
	// inspectExisting doesn't populate Token; mint one for this call.
	token, err := auth.IssueAgentToken(d.cfg.JWTSecret, agentID)
	if err != nil {
		return fmt.Errorf("issue agent token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint+"/refresh", nil)
	if err != nil {
		return fmt.Errorf("create refresh request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

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
func (d *Dispatcher) forward(ctx context.Context, c *container.Container, method, path string, body []byte, runID uuid.UUID, bridgeID *uuid.UUID, timeout time.Duration) (io.ReadCloser, error) {
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

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("forward to agent: %w", err)
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("agent returned %d: %s", resp.StatusCode, respBody)
	}
	return resp.Body, nil
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
