package container

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/config"
	"github.com/docker/docker/api/types/network"
	"github.com/google/uuid"
)

func TestReusableAgentToken(t *testing.T) {
	const secret = "container-token-test-secret"
	agentID := uuid.New()
	tokenV1, err := auth.IssueAgentToken(secret, agentID, 1)
	if err != nil {
		t.Fatal(err)
	}
	sameVersion, err := auth.IssueAgentToken(secret, agentID, 1)
	if err != nil {
		t.Fatal(err)
	}
	tokenV2, err := auth.IssueAgentToken(secret, agentID, 2)
	if err != nil {
		t.Fatal(err)
	}
	otherAgent, err := auth.IssueAgentToken(secret, uuid.New(), 1)
	if err != nil {
		t.Fatal(err)
	}

	if !reusableAgentToken(secret, tokenV1, sameVersion, time.Now()) {
		t.Fatal("same-profile, same-version token was not reusable")
	}
	if reusableAgentToken(secret, tokenV1, tokenV2, time.Now()) {
		t.Fatal("cross-version token was reusable")
	}
	if reusableAgentToken(secret, tokenV1, otherAgent, time.Now()) {
		t.Fatal("cross-agent token was reusable")
	}
	claims, err := auth.ValidateAgentToken(secret, tokenV1)
	if err != nil {
		t.Fatal(err)
	}
	if reusableAgentToken(secret, tokenV1, sameVersion, claims.ExpiresAt.Time.Add(-auth.AgentTokenRotationWindow+time.Second)) {
		t.Fatal("token inside the proactive rotation window was reusable")
	}
	if reusableAgentToken(secret, "", sameVersion, time.Now()) {
		t.Fatal("container token without the required profile was reusable")
	}
}

func TestAgentBuilderEntrypointPreparesOnlyToolserver(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "scripts", "agent-builder-entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("image carrier", func(t *testing.T) {
		cmd := exec.Command(script, "true")
		cmd.Dir = t.TempDir()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("entrypoint true: %v\n%s", err, out)
		} else if len(out) != 0 {
			t.Fatalf("entrypoint true output = %q, want none", out)
		}
	})

	t.Run("toolserver requires module", func(t *testing.T) {
		cmd := exec.Command(script, "toolserver")
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatal("entrypoint toolserver without go.mod succeeded")
		}
		if !strings.Contains(string(out), "toolserver workspace has no go.mod") {
			t.Fatalf("entrypoint error = %q", out)
		}
	})

	t.Run("toolserver prepares workspace", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module agent\n\ngo 1.26.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		binDir := filepath.Join(dir, "bin")
		if err := os.Mkdir(binDir, 0o755); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(dir, "commands.log")
		for name, body := range map[string]string{
			"go":         "#!/bin/sh\nprintf 'go %s\\n' \"$*\" >> \"$ENTRYPOINT_LOG\"\n",
			"toolserver": "#!/bin/sh\nprintf 'toolserver %s\\n' \"$*\" >> \"$ENTRYPOINT_LOG\"\n",
		} {
			if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(script, "toolserver", "-space-dir", dir)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"), "ENTRYPOINT_LOG="+logPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("entrypoint toolserver: %v\n%s", err, out)
		}
		got, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		want := "go mod tidy\ngo tool air toolchain install\ntoolserver -space-dir " + dir + "\n"
		if string(got) != want {
			t.Fatalf("commands:\n%s\nwant:\n%s", got, want)
		}
	})
}

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

	// Native mode: host-gateway alias present so agents reach host-run airlock.
	dev := buildAgentHostConfig(&config.Config{AgentHostGateway: true})
	if len(dev.ExtraHosts) != 1 || dev.ExtraHosts[0] != "host.docker.internal:host-gateway" {
		t.Errorf("dev ExtraHosts = %v, want [host.docker.internal:host-gateway]", dev.ExtraHosts)
	}
	liveLibs := buildAgentHostConfig(&config.Config{AgentLibsPathExplicit: true})
	if len(liveLibs.ExtraHosts) != 0 {
		t.Errorf("live libs ExtraHosts = %v, want none without AGENT_HOST_GATEWAY", liveLibs.ExtraHosts)
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

func TestBuildToolserverHostConfig(t *testing.T) {
	hc := buildToolserverHostConfig(&config.Config{AgentMemoryLimitBytes: 512 << 20}, nil)
	if hc.Init == nil || !*hc.Init {
		t.Fatal("Init is not enabled")
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 2048 {
		t.Fatalf("PidsLimit = %v, want 2048", hc.PidsLimit)
	}
	if hc.CPUShares != 512 || hc.OomScoreAdj != 500 {
		t.Fatalf("resources = CPU %d OOM %d", hc.CPUShares, hc.OomScoreAdj)
	}
	if hc.Memory != 512<<20 || hc.MemorySwap != 512<<20 {
		t.Fatalf("memory = (%d, %d)", hc.Memory, hc.MemorySwap)
	}
	wantDrops := []string{"AUDIT_WRITE", "KILL", "MKNOD", "NET_BIND_SERVICE", "NET_RAW"}
	if !slices.Equal(hc.CapDrop, wantDrops) {
		t.Fatalf("CapDrop = %v, want %v", hc.CapDrop, wantDrops)
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

func TestAgentNetworkCreateOptions(t *testing.T) {
	agentID := uuid.New().String()
	got := agentNetworkCreateOptions("prod", agentID)
	if got.Driver != "bridge" || !got.Internal {
		t.Fatalf("network policy = driver %q internal %v", got.Driver, got.Internal)
	}
	wantLabels := map[string]string{
		labelInstance: "prod",
		labelResource: resourceAgentNet,
		labelAgentID:  agentID,
	}
	for key, want := range wantLabels {
		if got.Labels[key] != want {
			t.Errorf("label %s = %q, want %q", key, got.Labels[key], want)
		}
	}
	if len(got.Labels) != len(wantLabels) {
		t.Errorf("labels = %v, want only %v", got.Labels, wantLabels)
	}
}

func TestValidateAgentNetwork(t *testing.T) {
	agentID := uuid.New().String()
	valid := network.Inspect{
		Name:     "prod-agent-net-" + agentID,
		Driver:   "bridge",
		Internal: true,
		Labels:   agentNetworkCreateOptions("prod", agentID).Labels,
	}
	if err := validateAgentNetwork(valid, "prod", agentID); err != nil {
		t.Fatalf("valid network rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*network.Inspect)
	}{
		{"external", func(n *network.Inspect) { n.Internal = false }},
		{"wrong driver", func(n *network.Inspect) { n.Driver = "overlay" }},
		{"wrong instance", func(n *network.Inspect) { n.Labels[labelInstance] = "other" }},
		{"wrong agent", func(n *network.Inspect) { n.Labels[labelAgentID] = uuid.NewString() }},
		{"wrong resource", func(n *network.Inspect) { n.Labels[labelResource] = "other" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := valid
			candidate.Labels = map[string]string{}
			for key, value := range valid.Labels {
				candidate.Labels[key] = value
			}
			tt.mutate(&candidate)
			if err := validateAgentNetwork(candidate, "prod", agentID); err == nil {
				t.Fatal("invalid network accepted")
			}
		})
	}
}

func TestAgentNetworkName(t *testing.T) {
	agentID := uuid.MustParse("12345678-1234-1234-1234-123456789abc")
	m := &DockerManager{cfg: &config.Config{InstanceID: "prod"}}
	if got, want := m.agentNetworkName(agentID), "prod-agent-net-12345678-1234-1234-1234-123456789abc"; got != want {
		t.Fatalf("agentNetworkName() = %q, want %q", got, want)
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
	m := &DockerManager{
		cfg:         &config.Config{InstanceID: "test"},
		inFlight:    make(map[string]int),
		idleTimeout: 10 * time.Minute,
	}
	name := m.agentName(id)
	m.active = map[string]*Container{name: {ID: "cid"}}
	m.lastActivity = map[string]time.Time{name: time.Now().Add(-time.Hour)}

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
	m := &DockerManager{
		cfg:         &config.Config{InstanceID: "test"},
		inFlight:    make(map[string]int),
		idleTimeout: 10 * time.Minute,
	}
	name := m.agentName(id)
	m.active = map[string]*Container{name: {ID: "cid"}}
	m.lastActivity = map[string]time.Time{name: time.Now().Add(-time.Hour)}

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
