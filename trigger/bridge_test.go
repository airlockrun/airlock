package trigger

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aircrypto "github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
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

func TestAddManagedBridgeSetsWebAppMenuImmediately(t *testing.T) {
	skipIfNoTriggerDB(t)
	ctx := context.Background()
	q := dbq.New(triggerTestDB.Pool())
	suffix := uuid.NewString()[:8]
	owner, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "menu-" + suffix + "@example.com",
		DisplayName: "Menu Owner",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	agent, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name:             "Menu Agent",
		Slug:             "menu-" + suffix,
		OwnerPrincipalID: owner.ID,
		Config:           []byte("{}"),
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	bridgeID := uuid.New()
	secretStore := secrets.NewLocal(aircrypto.New(make([]byte, 32)))
	ref := "bridge/" + bridgeID.String() + "/bot_token"
	encryptedToken, err := secretStore.Put(ctx, ref, "test-token")
	if err != nil {
		t.Fatalf("encrypt bot token: %v", err)
	}
	if _, err := q.CreateBridge(ctx, dbq.CreateBridgeParams{
		ID:                toPgUUID(bridgeID),
		Type:              "telegram",
		Name:              "managed-menu-" + suffix,
		BotTokenRef:       encryptedToken,
		BotUsername:       "managed_menu_" + suffix,
		AgentID:           agent.ID,
		OwnerPrincipalID:  owner.ID,
		Managed:           true,
		TelegramBotUserID: pgtype.Int8{Int64: 12345, Valid: true},
	}); err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}

	var menuBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case hasTelegramMethod(r, "getChatMenuButton"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":          false,
				"description": "temporary read failure",
			})
		case hasTelegramMethod(r, "setChatMenuButton"):
			if err := json.NewDecoder(r.Body).Decode(&menuBody); err != nil {
				t.Errorf("decode setChatMenuButton body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": true})
		case hasTelegramMethod(r, "getUpdates"):
			<-r.Context().Done()
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": true})
		}
	}))

	driver := NewTelegramDriverWithBaseURL(srv.URL, srv.Client())
	manager := NewBridgeManager(
		map[string]BridgeDriver{"telegram": driver},
		nil,
		triggerTestDB,
		secretStore,
		"test-hmac-secret",
		"https://airlock.example",
		func(slug string) string { return "https://" + slug + ".agents.example" },
		zap.NewNop(),
	)
	manager.ctx, manager.cancel = context.WithCancel(context.Background())
	defer func() {
		manager.cancel()
		manager.RemoveBridge(bridgeID)
		srv.CloseClientConnections()
		srv.Close()
	}()

	manager.AddBridge(bridgeID)

	if menuBody == nil {
		t.Fatal("setChatMenuButton was not called for managed bridge")
	}
	button, ok := menuBody["menu_button"].(map[string]any)
	if !ok {
		t.Fatalf("menu_button = %#v, want object", menuBody["menu_button"])
	}
	if got := button["type"]; got != "web_app" {
		t.Errorf("menu button type = %v, want web_app", got)
	}
	if got := button["text"]; got != "Open" {
		t.Errorf("menu button text = %v, want Open", got)
	}
	webApp, ok := button["web_app"].(map[string]any)
	if !ok {
		t.Fatalf("web_app = %#v, want object", button["web_app"])
	}
	wantURL := "https://" + agent.Slug + ".agents.example/__air/tg/start?b=" + bridgeID.String()
	if got := webApp["url"]; got != wantURL {
		t.Errorf("web app URL = %v, want %s", got, wantURL)
	}
}

func hasTelegramMethod(r *http.Request, method string) bool {
	return strings.HasSuffix(r.URL.Path, "/"+method)
}
