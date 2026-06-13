package container

import (
	"testing"
	"time"

	"github.com/airlockrun/airlock/config"
	"github.com/google/uuid"
)

func TestBuildAgentHostConfig(t *testing.T) {
	// Baseline (prod-shape): no dev flag, no memory cap, default runtime.
	hc := buildAgentHostConfig(&config.Config{})

	if len(hc.CapDrop) != 1 || hc.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL]", hc.CapDrop)
	}
	var hasNNP bool
	for _, o := range hc.SecurityOpt {
		if o == "no-new-privileges" {
			hasNNP = true
		}
	}
	if !hasNNP {
		t.Errorf("SecurityOpt = %v, want it to contain no-new-privileges", hc.SecurityOpt)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 1024 {
		t.Errorf("PidsLimit = %v, want 1024", hc.PidsLimit)
	}
	if hc.CPUShares != 512 {
		t.Errorf("CPUShares = %d, want 512", hc.CPUShares)
	}
	if hc.OomScoreAdj != 500 {
		t.Errorf("OomScoreAdj = %d, want 500", hc.OomScoreAdj)
	}
	// Prod: no host-gateway alias, no memory cap, default runtime.
	if len(hc.ExtraHosts) != 0 {
		t.Errorf("ExtraHosts = %v, want none in prod", hc.ExtraHosts)
	}
	if hc.Memory != 0 {
		t.Errorf("Memory = %d, want 0 (unlimited) when unset", hc.Memory)
	}
	if hc.Runtime != "" {
		t.Errorf("Runtime = %q, want \"\" (Docker default)", hc.Runtime)
	}

	// Dev: host-gateway alias present so agents reach host-run airlock.
	dev := buildAgentHostConfig(&config.Config{AgentLibsPathExplicit: true})
	if len(dev.ExtraHosts) != 1 || dev.ExtraHosts[0] != "host.docker.internal:host-gateway" {
		t.Errorf("dev ExtraHosts = %v, want [host.docker.internal:host-gateway]", dev.ExtraHosts)
	}

	// Memory cap applied (and swap pinned to it) only when configured.
	const lim = 512 * 1024 * 1024
	mem := buildAgentHostConfig(&config.Config{AgentMemoryLimitBytes: lim})
	if mem.Memory != lim || mem.MemorySwap != lim {
		t.Errorf("Memory/MemorySwap = %d/%d, want %d/%d", mem.Memory, mem.MemorySwap, lim, lim)
	}

	// gVisor runtime threads through.
	gv := buildAgentHostConfig(&config.Config{AgentRuntime: "runsc"})
	if gv.Runtime != "runsc" {
		t.Errorf("Runtime = %q, want runsc", gv.Runtime)
	}
}

func TestNetworkConfig(t *testing.T) {
	// Named network → single endpoint attachment.
	nc := networkConfig("agents")
	if len(nc.EndpointsConfig) != 1 {
		t.Fatalf("EndpointsConfig = %v, want one entry", nc.EndpointsConfig)
	}
	if _, ok := nc.EndpointsConfig["agents"]; !ok {
		t.Errorf("EndpointsConfig missing 'agents': %v", nc.EndpointsConfig)
	}

	// Empty network → no endpoints (daemon default network).
	if got := networkConfig(""); len(got.EndpointsConfig) != 0 {
		t.Errorf("empty network: EndpointsConfig = %v, want none", got.EndpointsConfig)
	}
}

func TestIdleContainersToStop(t *testing.T) {
	now := time.Now()
	m := &DockerManager{
		active: map[string]*Container{
			"a": {ID: "id-a"},
			"b": {ID: "id-b"},
			"c": {ID: "id-c"},
		},
		lastActivity: map[string]time.Time{
			"a": now.Add(-20 * time.Minute), // idle, idle → stop
			"b": now.Add(-20 * time.Minute), // idle but in-flight → keep
			"c": now.Add(-1 * time.Minute),  // recently used → keep
		},
		inFlight:    map[string]int{"b": 1},
		idleTimeout: 10 * time.Minute,
	}

	got := m.idleContainersToStop(now)
	if len(got) != 1 || got[0].name != "a" {
		t.Fatalf("expected only [a] to be stopped, got %+v", got)
	}
}

// TestMarkBusyExemptsFromReaping is the regression test for a run that
// outlasts the idle timeout: while a request is in flight the container
// must survive a reap pass, and MarkIdle must restart the idle clock.
func TestMarkBusyExemptsFromReaping(t *testing.T) {
	id := uuid.New()
	name := agentName(id)
	m := &DockerManager{
		active:       map[string]*Container{name: {ID: "cid"}},
		lastActivity: map[string]time.Time{name: time.Now().Add(-time.Hour)},
		inFlight:     make(map[string]int),
		idleTimeout:  10 * time.Minute,
	}

	// In flight: not reapable despite an hour-old lastActivity stamp.
	m.MarkBusy(id)
	if got := m.idleContainersToStop(time.Now()); len(got) != 0 {
		t.Fatalf("in-flight container must not be reaped, got %+v", got)
	}

	// Request finished: MarkIdle refreshed the clock, count cleared.
	m.MarkIdle(id)
	if _, ok := m.inFlight[name]; ok {
		t.Fatalf("inFlight entry should be deleted once the count hits zero")
	}
	if got := m.idleContainersToStop(time.Now()); len(got) != 0 {
		t.Fatalf("MarkIdle should restart the idle clock, got %+v", got)
	}

	// Once the timeout elapses past the MarkIdle stamp, it is reapable.
	m.lastActivity[name] = time.Now().Add(-11 * time.Minute)
	if got := m.idleContainersToStop(time.Now()); len(got) != 1 {
		t.Fatalf("expected reap after the idle timeout, got %+v", got)
	}
}

// TestMarkBusyNested verifies overlapping requests on one container: the
// container only becomes reapable after the last MarkIdle.
func TestMarkBusyNested(t *testing.T) {
	id := uuid.New()
	name := agentName(id)
	m := &DockerManager{
		active:       map[string]*Container{name: {ID: "cid"}},
		lastActivity: map[string]time.Time{name: time.Now().Add(-time.Hour)},
		inFlight:     make(map[string]int),
		idleTimeout:  10 * time.Minute,
	}

	m.MarkBusy(id)
	m.MarkBusy(id)
	m.MarkIdle(id)
	m.lastActivity[name] = time.Now().Add(-time.Hour) // undo MarkIdle's refresh
	if got := m.idleContainersToStop(time.Now()); len(got) != 0 {
		t.Fatalf("still one request in flight, must not be reaped, got %+v", got)
	}

	m.MarkIdle(id)
	m.lastActivity[name] = time.Now().Add(-time.Hour)
	if got := m.idleContainersToStop(time.Now()); len(got) != 1 {
		t.Fatalf("last request done, expected reap, got %+v", got)
	}
}
