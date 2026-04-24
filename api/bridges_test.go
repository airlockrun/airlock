package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

func testBridgeHandler(telegramSrv *httptest.Server) *bridgeHandler {
	td := trigger.NewTelegramDriver(zap.NewNop())
	if telegramSrv != nil {
		td = trigger.NewTelegramDriverWithBaseURL(telegramSrv.URL, telegramSrv.Client())
	}
	return &bridgeHandler{
		db:        testDB,
		encryptor: testEncryptor(),
		telegram:  td,
		logger:    zap.NewNop(),
	}
}

func TestCreateAgentBridge(t *testing.T) {
	skipIfNoDB(t)

	// Mock Telegram API (getMe).
	telegramSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"result": map[string]any{
				"id":       12345,
				"username": "test_bot",
			},
		})
	}))
	defer telegramSrv.Close()

	bh := testBridgeHandler(telegramSrv)
	agentID, userID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
	})

	body := map[string]string{
		"name":     "My Agent Bot",
		"token":    "fake-bot-token",
		"agent_id": agentID.String(),
	}
	req := userRequestJSON(t, "POST", "/api/v1/bridges", userID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("CreateBridge: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.BridgeInfo
	protojson.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.BotUsername != "test_bot" {
		t.Errorf("bot_username = %q, want test_bot", resp.BotUsername)
	}
	if resp.AgentId != agentID.String() {
		t.Errorf("agent_id = %q, want %s", resp.AgentId, agentID)
	}
}

func TestCreateSystemBridgeRequiresAdmin(t *testing.T) {
	skipIfNoDB(t)

	telegramSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"username": "sys_bot"}})
	}))
	defer telegramSrv.Close()

	bh := testBridgeHandler(telegramSrv)
	_, userID := testAgentAndUser(t) // member role

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
	})

	// System bridge (no agent_id) with member role → should fail.
	body := map[string]string{"name": "System Bot", "token": "fake-token"}
	req := userRequestJSON(t, "POST", "/api/v1/bridges", userID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("system bridge as member: status = %d, want 403", rec.Code)
	}
}

func TestListAndDeleteBridge(t *testing.T) {
	skipIfNoDB(t)

	telegramSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"username": "del_bot"}})
	}))
	defer telegramSrv.Close()

	bh := testBridgeHandler(telegramSrv)
	agentID, userID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
		r.Get("/api/v1/bridges", bh.ListBridges)
		r.Delete("/api/v1/bridges/{bridgeID}", bh.DeleteBridge)
	})

	// Create bridge.
	body := map[string]string{"name": "Del Bot", "token": "fake-token", "agent_id": agentID.String()}
	req := userRequestJSON(t, "POST", "/api/v1/bridges", userID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status = %d", rec.Code)
	}
	var created airlockv1.BridgeInfo
	protojson.Unmarshal(rec.Body.Bytes(), &created)

	// List — should contain the bridge.
	req = userRequestJSON(t, "GET", "/api/v1/bridges", userID, nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status = %d", rec.Code)
	}
	var listResp airlockv1.ListBridgesResponse
	protojson.Unmarshal(rec.Body.Bytes(), &listResp)
	found := false
	for _, b := range listResp.Bridges {
		if b.Id == created.Id {
			found = true
		}
	}
	if !found {
		t.Error("created bridge not found in list")
	}

	// Delete.
	req = userRequestJSON(t, "DELETE",
		fmt.Sprintf("/api/v1/bridges/%s", created.Id), userID, nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete: status = %d, want 204; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateBridgeBadToken(t *testing.T) {
	skipIfNoDB(t)

	// Mock Telegram API that returns an error for getMe.
	telegramSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "description": "Unauthorized"})
	}))
	defer telegramSrv.Close()

	bh := testBridgeHandler(telegramSrv)
	agentID, userID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
	})

	body := map[string]string{"name": "Bad Bot", "token": "invalid-token", "agent_id": agentID.String()}
	req := userRequestJSON(t, "POST", "/api/v1/bridges", userID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad token: status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
}
