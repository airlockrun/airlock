package container

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

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
