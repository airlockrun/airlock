package apitest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"

	"github.com/airlockrun/airlock/container"
	"github.com/google/uuid"
)

// FakeContainerManager implements container.ContainerManager backed by
// per-agent httptest.Server instances. Tests register an http.Handler
// per agent (typically built with Upstream); StartAgent returns the
// recorded endpoint so the dispatcher dials a real local HTTP server
// over the loopback. No Docker involvement.
//
// MarkBusy/MarkIdle increment counters tests can read to assert the
// dispatcher correctly brackets every forwarded request — the reaper
// invariant ([airlock/AGENTS.md] Agent Execution).
type FakeContainerManager struct {
	mu      sync.Mutex
	servers map[uuid.UUID]*httptest.Server
	tokens  map[uuid.UUID]string
	busyCnt map[uuid.UUID]int
	idleCnt map[uuid.UUID]int
	stopped map[string]bool
	starts  map[uuid.UUID]int
	stopErr map[uuid.UUID]error
}

func NewFakeContainerManager() *FakeContainerManager {
	return &FakeContainerManager{
		servers: make(map[uuid.UUID]*httptest.Server),
		tokens:  make(map[uuid.UUID]string),
		busyCnt: make(map[uuid.UUID]int),
		idleCnt: make(map[uuid.UUID]int),
		stopped: make(map[string]bool),
		starts:  make(map[uuid.UUID]int),
		stopErr: make(map[uuid.UUID]error),
	}
}

// RegisterAgent wires a handler for the given agent. The handler must
// honour the dispatcher's HTTP contract:
//   - POST /prompt with X-Run-ID and Bearer agentToken — stream NDJSON.
//   - POST /__air/tool/{name} for user tool calls — return JSON.
//
// token is the bearer the test expects upstream to validate against.
// Most tests pass a zero token and ignore it; the harness still puts it
// in the Container record for completeness.
func (m *FakeContainerManager) RegisterAgent(agentID uuid.UUID, h http.Handler, token string) {
	srv := httptest.NewServer(h)
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.servers[agentID]; ok {
		old.Close()
	}
	m.servers[agentID] = srv
	m.tokens[agentID] = token
}

// Close shuts every registered httptest.Server down. Called from the
// harness teardown via t.Cleanup.
//
// CloseClientConnections runs first so handlers parked on r.Context()
// unblock as soon as the underlying TCP socket goes away — otherwise
// srv.Close() blocks waiting for the handler to return and a failing
// test can hang the package until `go test -timeout` SIGQUITs it.
func (m *FakeContainerManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.servers {
		s.CloseClientConnections()
		s.Close()
	}
	m.servers = nil
}

// BusyCount / IdleCount expose the MarkBusy/MarkIdle counters for
// assertion. Tests typically expect them equal at end-of-flow.
func (m *FakeContainerManager) BusyCount(agentID uuid.UUID) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.busyCnt[agentID]
}
func (m *FakeContainerManager) IdleCount(agentID uuid.UUID) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.idleCnt[agentID]
}

// StartCount reports how many times StartAgent was invoked for an
// agent — non-zero means dispatcher.EnsureRunning fired.
func (m *FakeContainerManager) StartCount(agentID uuid.UUID) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.starts[agentID]
}

// SetStopError configures StopAgent to fail for an agent. Passing nil clears
// the failure so tests can exercise a successful retry.
func (m *FakeContainerManager) SetStopError(agentID uuid.UUID, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.stopErr, agentID)
		return
	}
	m.stopErr[agentID] = err
}

var errAgentNotRegistered = errors.New("apitest: agent not registered with FakeContainerManager")

// --- container.ContainerManager implementation ---

func (m *FakeContainerManager) StartAgent(ctx context.Context, opts container.AgentOpts) (*container.Container, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	srv, ok := m.servers[opts.AgentID]
	if !ok {
		return nil, errAgentNotRegistered
	}
	m.starts[opts.AgentID]++
	return &container.Container{
		ID:       "fake-" + opts.AgentID.String(),
		Name:     "fake-" + opts.AgentID.String(),
		Endpoint: srv.URL,
		Token:    opts.Token,
	}, nil
}

func (m *FakeContainerManager) GetRunning(ctx context.Context, agentID uuid.UUID) (*container.Container, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	srv, ok := m.servers[agentID]
	if !ok {
		return nil, nil
	}
	return &container.Container{
		ID:       "fake-" + agentID.String(),
		Name:     "fake-" + agentID.String(),
		Endpoint: srv.URL,
		Token:    m.tokens[agentID],
	}, nil
}

func (m *FakeContainerManager) RunningAgents(ctx context.Context, agentIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[uuid.UUID]bool, len(agentIDs))
	for _, id := range agentIDs {
		_, out[id] = m.servers[id]
	}
	return out, nil
}

func (m *FakeContainerManager) StopAgent(ctx context.Context, agentID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopped[agentID.String()] = true
	return m.stopErr[agentID]
}

func (m *FakeContainerManager) MarkBusy(agentID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.busyCnt[agentID]++
}

func (m *FakeContainerManager) MarkIdle(agentID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idleCnt[agentID]++
}

// Toolserver methods are no-ops — the harness never drives builds.
func (m *FakeContainerManager) StartToolserver(ctx context.Context, opts container.ToolserverOpts) (*container.Container, error) {
	return nil, errors.New("apitest: StartToolserver not supported by FakeContainerManager")
}
func (m *FakeContainerManager) StopToolserver(ctx context.Context, name string) error { return nil }
func (m *FakeContainerManager) KillToolserver(ctx context.Context, name string) error { return nil }
func (m *FakeContainerManager) CaptureToolserverDiagnostics(ctx context.Context, name, reason string) error {
	return nil
}
func (m *FakeContainerManager) RemoveImage(ctx context.Context, imageRef string) error { return nil }

// LockSwap returns a no-op release fn — the apitest harness doesn't race
// builds with triggers, so swap serialisation has nothing to gate.
func (m *FakeContainerManager) LockSwap(agentID uuid.UUID) func() {
	return func() {}
}
