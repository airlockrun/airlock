package trigger

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestRemoveBridge_CancelsRegisteredPoller verifies that RemoveBridge
// (a) calls the stored cancel func and (b) removes the map entry. Without
// this, deleted bridges keep polling their platform tokens — and when a
// replacement bridge with the same token is created, two pollers race for
// the same Telegram getUpdates session and both get 409 Conflict.
func TestRemoveBridge_CancelsRegisteredPoller(t *testing.T) {
	m := &BridgeManager{
		pollers: make(map[uuid.UUID]*pollerHandle),
	}

	bridgeID := uuid.New()
	var called atomic.Int32
	m.pollers[bridgeID] = &pollerHandle{cancel: func() { called.Add(1) }}

	m.RemoveBridge(bridgeID)

	if called.Load() != 1 {
		t.Errorf("cancel func called %d times, want 1", called.Load())
	}
	if _, ok := m.pollers[bridgeID]; ok {
		t.Error("expected map entry to be removed")
	}
}

func TestRemoveBridge_UnknownIDIsNoOp(t *testing.T) {
	m := &BridgeManager{
		pollers: make(map[uuid.UUID]*pollerHandle),
	}

	// Should not panic on an ID that was never registered.
	m.RemoveBridge(uuid.New())
}

func TestCancelPoller_ConcurrentSafe(t *testing.T) {
	m := &BridgeManager{
		pollers: make(map[uuid.UUID]*pollerHandle),
	}

	// Many concurrent AddBridge-style registrations and RemoveBridge calls
	// on the same ID must not deadlock or panic.
	bridgeID := uuid.New()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			m.pollersMu.Lock()
			m.pollers[bridgeID] = &pollerHandle{cancel: func() {}}
			m.pollersMu.Unlock()
		}
		close(done)
	}()
	go func() {
		for i := 0; i < 100; i++ {
			m.RemoveBridge(bridgeID)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deadlock / timeout")
	}
}

// pickConfirmationBody picks a body string from a PermissionAsked
// metadata bag — code first, then args (pretty-printed when JSON), then
// message, and "" when nothing useful is present.
func TestPickConfirmationBody(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"code wins", map[string]any{"code": "console.log(1)", "args": "{}", "message": "x"}, "console.log(1)"},
		{"args JSON pretty-printed", map[string]any{"args": `{"agent":"spotify"}`}, "{\n  \"agent\": \"spotify\"\n}"},
		{"args non-JSON passthrough", map[string]any{"args": "spotify"}, "spotify"},
		{"message fallback", map[string]any{"message": "polling tripped"}, "polling tripped"},
		{"empty inputs ignored", map[string]any{"code": "", "args": "", "message": ""}, ""},
		{"nil metadata", nil, ""},
		{"non-string values skipped", map[string]any{"code": 42, "args": []string{"a"}, "message": "fallback"}, "fallback"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := pickConfirmationBody(tt.in); got != tt.want {
				t.Errorf("pickConfirmationBody = %q, want %q", got, tt.want)
			}
		})
	}
}
