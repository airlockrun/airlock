package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// testNoopBridgeMgr satisfies bridgessvc.BridgeManager without spinning
// up a real poller — the test only cares that lifecycle methods exist.
type testNoopBridgeMgr struct{}

func (testNoopBridgeMgr) AddBridge(uuid.UUID)      {}
func (testNoopBridgeMgr) TeardownBridge(uuid.UUID) {}
func (testNoopBridgeMgr) RemoveBridge(uuid.UUID)   {}

func testBridgeHandler(telegramSrv *httptest.Server) *bridgeHandler {
	td := trigger.NewTelegramDriver(zap.NewNop())
	if telegramSrv != nil {
		td = trigger.NewTelegramDriverWithBaseURL(telegramSrv.URL, telegramSrv.Client())
	}
	return newBridgeHandler(bridgessvc.New(
		testDB, testEncryptor(), td, testNoopBridgeMgr{}, zap.NewNop(),
	))
}

// telegramGetMeServer mocks the Telegram Bot API: every method returns the
// same getMe result shape (id/username/can_manage_bots). Driver.Init's
// getUpdates call gets the object-shaped result, fails to parse, and is
// swallowed (non-fatal) — same as the other tests' single-shape mocks.
func telegramGetMeServer(id int64, username string, canManageBots bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"result": map[string]any{
				"id":              id,
				"username":        username,
				"can_manage_bots": canManageBots,
			},
		})
	}))
}

// TestCreateManagerBridge: an admin can create a system+manager Telegram
// bridge when the bot's can_manage_bots is enabled.
func TestCreateManagerBridge(t *testing.T) {
	skipIfNoDB(t)

	srv := telegramGetMeServer(50001, "mgr_bot", true)
	defer srv.Close()

	bh := testBridgeHandler(srv)
	_, userID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
	})

	// No agent_id → system bridge; is_manager → also the manager. Both gates
	// are admin, so an admin clears them.
	body := map[string]any{"name": "Manager Bot", "token": "fake-token", "is_manager": true}
	req := requestJSONAs(t, "POST", "/api/v1/bridges", userID, "admin", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("create manager bridge: status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var resp airlockv1.BridgeInfo
	decodeProtoResp(t, rec, &resp)
	if !resp.IsManager {
		t.Error("is_manager = false, want true")
	}
}

// TestCreateManagerBridgeRequiresCapability: is_manager is refused when the
// bot doesn't have can_manage_bots enabled in BotFather.
func TestCreateManagerBridgeRequiresCapability(t *testing.T) {
	skipIfNoDB(t)

	srv := telegramGetMeServer(50002, "nocap_bot", false) // can_manage_bots: false
	defer srv.Close()

	bh := testBridgeHandler(srv)
	_, userID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
	})

	body := map[string]any{"name": "No Cap Bot", "token": "fake-token", "is_manager": true}
	req := requestJSONAs(t, "POST", "/api/v1/bridges", userID, "admin", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("manager bridge without can_manage_bots: status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
}

// TestCreateManagerBridgeRequiresAdmin: a manager-role user (agent-admin on
// the target) can create an ordinary agent bridge but not flag it is_manager.
func TestCreateManagerBridgeRequiresAdmin(t *testing.T) {
	skipIfNoDB(t)

	srv := telegramGetMeServer(50003, "mgr_bot", true)
	defer srv.Close()

	bh := testBridgeHandler(srv)
	agentID, userID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
	})

	// Agent-bound (so the system gate doesn't fire first) + is_manager as a
	// manager-role user → blocked by the manager-config (admin) gate.
	body := map[string]any{"name": "Mgr", "token": "fake-token", "agent_id": agentID.String(), "is_manager": true}
	req := requestJSONAs(t, "POST", "/api/v1/bridges", userID, "manager", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("is_manager as manager role: status = %d, want 403; body: %s", rec.Code, rec.Body.String())
	}
}

// TestCreateBridgeOneListenerPerBot: a given Telegram bot can back only one
// bridge — a second create for the same bot id is rejected (one getUpdates
// consumer per bot).
func TestCreateBridgeOneListenerPerBot(t *testing.T) {
	skipIfNoDB(t)

	srv := telegramGetMeServer(50004, "dup_bot", false) // same id for every getMe
	defer srv.Close()

	bh := testBridgeHandler(srv)
	agentID, userID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
	})

	first := map[string]any{"name": "First", "token": "fake-token", "agent_id": agentID.String()}
	req := requestJSONAs(t, "POST", "/api/v1/bridges", userID, "manager", first)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first create: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	// Second bridge on the same agent, same bot id (mock returns id 50004
	// again) → rejected by the one-listener-per-bot guard.
	second := map[string]any{"name": "Second", "token": "fake-token-2", "agent_id": agentID.String()}
	req = requestJSONAs(t, "POST", "/api/v1/bridges", userID, "manager", second)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("second bridge for same bot: status = %d, want 400; body: %s", rec.Code, rec.Body.String())
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
	// Manager role — `user` role is now blocked from any bridge create.
	req := requestJSONAs(t, "POST", "/api/v1/bridges", userID, "manager", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("CreateBridge: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.BridgeInfo
	decodeProtoResp(t, rec, &resp)
	if resp.BotUsername != "test_bot" {
		t.Errorf("bot_username = %q, want test_bot", resp.BotUsername)
	}
	if resp.AgentId != agentID.String() {
		t.Errorf("agent_id = %q, want %s", resp.AgentId, agentID)
	}
	if resp.Owner == nil {
		t.Errorf("owner unset; expected creator metadata")
	}
}

// TestCreateBridgeUserRoleForbidden asserts that the `user` tenant role
// is not allowed to create bridges; manager and admin paths are covered
// by TestCreateAgentBridge / TestCreateSystemBridgeRequiresAdmin.
func TestCreateBridgeUserRoleForbidden(t *testing.T) {
	skipIfNoDB(t)

	bh := testBridgeHandler(nil)
	agentID, userID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
	})

	body := map[string]string{"name": "Nope", "token": "fake", "agent_id": agentID.String()}
	req := requestJSONAs(t, "POST", "/api/v1/bridges", userID, "user", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("create as user role: status = %d, want 403; body: %s", rec.Code, rec.Body.String())
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
	_, userID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
	})

	// System bridge (is_system) as a manager role → 403 (admin-only).
	body := map[string]any{"name": "System Bot", "token": "fake-token", "isSystem": true}
	req := requestJSONAs(t, "POST", "/api/v1/bridges", userID, "manager", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("system bridge as manager: status = %d, want 403", rec.Code)
	}

	// No agent + not system → unbound bridge, which a manager MAY create.
	// Regression guard: empty agent_id must not be inferred as a system bridge.
	unbound := map[string]any{"name": "Unbound Bot", "token": "fake-token"}
	req = requestJSONAs(t, "POST", "/api/v1/bridges", userID, "manager", unbound)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("unbound bridge as manager: status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
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

	// Manager role creates the bridge — only manager and admin are
	// permitted on this endpoint.
	body := map[string]string{"name": "Del Bot", "token": "fake-token", "agent_id": agentID.String()}
	req := requestJSONAs(t, "POST", "/api/v1/bridges", userID, "manager", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status = %d", rec.Code)
	}
	var created airlockv1.BridgeInfo
	decodeProtoResp(t, rec, &created)

	// List — should contain the bridge (user is the agent's creator, so
	// they're auto-added as a member; ListBridgesAccessible returns it).
	req = userRequestJSON(t, "GET", "/api/v1/bridges", userID, nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status = %d", rec.Code)
	}
	var listResp airlockv1.ListBridgesResponse
	decodeProtoResp(t, rec, &listResp)
	found := false
	for _, b := range listResp.Bridges {
		if b.Id == created.Id {
			found = true
			if b.Owner == nil {
				t.Errorf("listed bridge has no owner; expected creator metadata")
			}
		}
	}
	if !found {
		t.Error("created bridge not found in list")
	}

	// Delete (creator can delete their own bridges).
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
	req := requestJSONAs(t, "POST", "/api/v1/bridges", userID, "manager", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad token: status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateBridgeAdminCanReassignOthersBridge confirms admins can
// reassign any user's bridge to an agent they have admin access on —
// the admin escape in service/bridges.Update.
func TestUpdateBridgeAdminCanReassignOthersBridge(t *testing.T) {
	skipIfNoDB(t)

	telegramSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": map[string]any{"username": "owned_bot"}})
	}))
	defer telegramSrv.Close()

	bh := testBridgeHandler(telegramSrv)
	agentID, ownerID := testAgentAndUser(t)
	otherAgentID, adminID := testAgentAndUser(t) // distinct user; we'll act as them as admin

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/bridges", bh.CreateBridge)
		r.Put("/api/v1/bridges/{bridgeID}", bh.UpdateBridge)
	})

	// Owner creates a bridge bound to their agent.
	body := map[string]string{"name": "Owner Bot", "token": "fake-token", "agent_id": agentID.String()}
	req := requestJSONAs(t, "POST", "/api/v1/bridges", ownerID, "manager", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status = %d", rec.Code)
	}
	var created airlockv1.BridgeInfo
	decodeProtoResp(t, rec, &created)

	// Admin (different user) reassigns to their own agent.
	updateBody := map[string]string{"agent_id": otherAgentID.String()}
	req = requestJSONAs(t, "PUT",
		fmt.Sprintf("/api/v1/bridges/%s", created.Id), adminID, "admin", updateBody)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("admin reassign someone else's bridge: status = %d, want 200; body: %s",
			rec.Code, rec.Body.String())
	}
}
