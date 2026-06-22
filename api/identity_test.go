package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	identitysvc "github.com/airlockrun/airlock/service/identity"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

const testHMACSecret = "test-hmac-secret"

func testIdentityService(td *trigger.TelegramDriver) *identitysvc.Service {
	return identitysvc.New(
		testDB, testEncryptor(),
		telegramIdentityAdapter{d: td},
		zap.NewNop(),
	)
}

func testIdentityHandler() *identityHandler {
	return newIdentityHandler(
		testIdentityService(trigger.NewTelegramDriver(zap.NewNop())),
		testHMACSecret,
		"http://localhost:8080",
	)
}

// testIdentityHandlerWithTelegram builds an identityHandler wired to a mock
// Telegram server so the preview endpoint can resolve display info without
// hitting api.telegram.org.
func testIdentityHandlerWithTelegram(srv *httptest.Server) *identityHandler {
	return newIdentityHandler(
		testIdentityService(trigger.NewTelegramDriverWithBaseURL(srv.URL, srv.Client())),
		testHMACSecret,
		"http://localhost:8080",
	)
}

// createTestBridgeWithToken inserts a bridge with the given raw token (will
// be encrypted with testEncryptor) so the preview handler can decrypt it at
// read time. Returns the bridge UUID.
func createTestBridgeWithToken(t *testing.T, rawToken, botUsername string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	enc, err := testEncryptor().Put(ctx, "bridge/new/bot_token", rawToken)
	if err != nil {
		t.Fatalf("encrypt token: %v", err)
	}
	var bridgeID uuid.UUID
	err = testDB.Pool().QueryRow(ctx,
		`INSERT INTO bridges (type, name, bot_token_ref, bot_username, status, is_system, config, settings)
		 VALUES ('telegram', $1, $2, $3, 'active', false, '{}'::jsonb, '{}'::jsonb) RETURNING id`,
		"preview-"+uuid.New().String()[:8], enc, botUsername,
	).Scan(&bridgeID)
	if err != nil {
		t.Fatalf("insert bridge: %v", err)
	}
	return bridgeID
}

func signAuthExternal(platform, bridgeID, uid string) (ts, sig string) {
	tsVal := strconv.FormatInt(time.Now().Unix(), 10)
	payload := platform + ":" + bridgeID + ":" + uid + ":" + tsVal
	mac := hmac.New(sha256.New, []byte(testHMACSecret))
	mac.Write([]byte(payload))
	return tsVal, hex.EncodeToString(mac.Sum(nil))
}

func TestAuthExternalRedirects(t *testing.T) {
	skipIfNoDB(t)
	ih := testIdentityHandler()

	// AuthExternal is a simple redirect — no auth required, no validation.
	router := chi.NewRouter()
	router.Get("/auth-external", ih.AuthExternal)

	req := httptest.NewRequest("GET", "/auth-external?platform=telegram&uid=123&ts=1&sig=abc", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("AuthExternal: status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/link-identity?") {
		t.Errorf("redirect location = %q, want /link-identity?...", loc)
	}
}

func TestLinkIdentity(t *testing.T) {
	skipIfNoDB(t)
	ih := testIdentityHandler()
	_, userID := testAgentAndUser(t)

	const bridgeID = "00000000-0000-0000-0000-000000000001"
	const platformUID = "99001122"

	linkRouter := userRouter(func(r chi.Router) {
		r.Post("/api/v1/link-identity", ih.LinkIdentity)
	})
	listRouter := userRouter(func(r chi.Router) {
		r.Get("/api/v1/identities", ih.ListIdentities)
	})
	unlinkRouter := userRouter(func(r chi.Router) {
		r.Delete("/api/v1/identities/{identityID}", ih.UnlinkIdentity)
	})

	t.Run("link", func(t *testing.T) {
		ts, sig := signAuthExternal("telegram", bridgeID, platformUID)
		url := fmt.Sprintf("/api/v1/link-identity?platform=telegram&bridge=%s&uid=%s&ts=%s&sig=%s",
			bridgeID, platformUID, ts, sig)
		req := userRequestJSON(t, "POST", url, userID, nil)
		rec := httptest.NewRecorder()
		linkRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("LinkIdentity: status = %d, want 204; body: %s", rec.Code, rec.Body.String())
		}
	})

	var identityID string
	t.Run("list after link", func(t *testing.T) {
		req := userRequestJSON(t, "GET", "/api/v1/identities", userID, nil)
		rec := httptest.NewRecorder()
		listRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ListIdentities: status = %d", rec.Code)
		}
		var listResp airlockv1.ListPlatformIdentitiesResponse
		decodeProtoResp(t, rec, &listResp)
		for _, id := range listResp.Identities {
			if id.Platform == "telegram" && id.PlatformUserId == platformUID {
				identityID = id.Id
			}
		}
		if identityID == "" {
			t.Fatal("linked identity not found in list")
		}
	})

	t.Run("unlink", func(t *testing.T) {
		if identityID == "" {
			t.Skip("link step did not produce an identity ID")
		}
		req := userRequestJSON(t, "DELETE",
			fmt.Sprintf("/api/v1/identities/%s", identityID), userID, nil)
		rec := httptest.NewRecorder()
		unlinkRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("Unlink: status = %d, want 204", rec.Code)
		}
	})

	t.Run("list after unlink", func(t *testing.T) {
		if identityID == "" {
			t.Skip("link step did not produce an identity ID")
		}
		req := userRequestJSON(t, "GET", "/api/v1/identities", userID, nil)
		rec := httptest.NewRecorder()
		listRouter.ServeHTTP(rec, req)
		var listResp airlockv1.ListPlatformIdentitiesResponse
		decodeProtoResp(t, rec, &listResp)
		for _, id := range listResp.Identities {
			if id.Id == identityID {
				t.Error("identity should be gone after unlink")
			}
		}
	})
}

func TestLinkIdentityBadSignature(t *testing.T) {
	skipIfNoDB(t)
	ih := testIdentityHandler()
	_, userID := testAgentAndUser(t)

	const bridgeID = "00000000-0000-0000-0000-000000000001"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	url := fmt.Sprintf("/api/v1/link-identity?platform=telegram&bridge=%s&uid=12345&ts=%s&sig=badsignature", bridgeID, ts)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/link-identity", ih.LinkIdentity)
	})
	req := userRequestJSON(t, "POST", url, userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad sig: status = %d, want 400", rec.Code)
	}
}

func TestLinkIdentityExpiredTimestamp(t *testing.T) {
	skipIfNoDB(t)
	ih := testIdentityHandler()
	_, userID := testAgentAndUser(t)

	// Use a timestamp from 15 minutes ago.
	const bridgeID = "00000000-0000-0000-0000-000000000001"
	oldTS := strconv.FormatInt(time.Now().Add(-15*time.Minute).Unix(), 10)
	payload := "telegram:" + bridgeID + ":12345:" + oldTS
	mac := hmac.New(sha256.New, []byte(testHMACSecret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	url := fmt.Sprintf("/api/v1/link-identity?platform=telegram&bridge=%s&uid=12345&ts=%s&sig=%s", bridgeID, oldTS, sig)

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/link-identity", ih.LinkIdentity)
	})
	req := userRequestJSON(t, "POST", url, userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expired ts: status = %d, want 400", rec.Code)
	}
}

func TestLinkIdentityPreview(t *testing.T) {
	skipIfNoDB(t)
	_, userID := testAgentAndUser(t)

	// Mock Telegram getChat → respond with a known user profile.
	var gotChatID string
	telegramSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if v, ok := body["chat_id"].(string); ok {
			gotChatID = v
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"result": map[string]any{
				"id":         55667788,
				"username":   "alice_tg",
				"first_name": "Alice",
				"last_name":  "Wonder",
			},
		})
	}))
	defer telegramSrv.Close()

	ih := testIdentityHandlerWithTelegram(telegramSrv)
	bridgeID := createTestBridgeWithToken(t, "fake-token", "preview_bot")

	ts, sig := signAuthExternal("telegram", bridgeID.String(), "55667788")
	url := fmt.Sprintf("/api/v1/link-identity/preview?platform=telegram&bridge=%s&uid=55667788&ts=%s&sig=%s",
		bridgeID, ts, sig)

	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/link-identity/preview", ih.LinkIdentityPreview)
	})
	req := userRequestJSON(t, "GET", url, userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("preview: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.LinkIdentityPreviewResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal preview: %v", err)
	}

	if resp.Platform != "telegram" {
		t.Errorf("Platform = %q, want telegram", resp.Platform)
	}
	if resp.BotUsername != "preview_bot" {
		t.Errorf("BotUsername = %q, want preview_bot", resp.BotUsername)
	}
	if resp.PlatformUserId != "55667788" {
		t.Errorf("PlatformUserId = %q, want 55667788", resp.PlatformUserId)
	}
	if resp.PlatformUsername != "alice_tg" {
		t.Errorf("PlatformUsername = %q, want alice_tg", resp.PlatformUsername)
	}
	if resp.PlatformDisplayName != "Alice Wonder" {
		t.Errorf("PlatformDisplayName = %q, want Alice Wonder", resp.PlatformDisplayName)
	}
	if resp.CurrentUserEmail == "" {
		t.Error("CurrentUserEmail is empty")
	}
	if gotChatID != "55667788" {
		t.Errorf("telegram getChat chat_id = %q, want 55667788", gotChatID)
	}
}

func TestLinkIdentityPreviewBadSignature(t *testing.T) {
	skipIfNoDB(t)
	_, userID := testAgentAndUser(t)

	ih := testIdentityHandler()
	bridgeID := createTestBridgeWithToken(t, "fake-token", "preview_bot")

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	url := fmt.Sprintf("/api/v1/link-identity/preview?platform=telegram&bridge=%s&uid=1&ts=%s&sig=wrong",
		bridgeID, ts)

	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/link-identity/preview", ih.LinkIdentityPreview)
	})
	req := userRequestJSON(t, "GET", url, userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad sig: status = %d, want 400", rec.Code)
	}
}

func TestLinkIdentityPreviewBridgePlatformMismatch(t *testing.T) {
	skipIfNoDB(t)
	_, userID := testAgentAndUser(t)

	ih := testIdentityHandler()
	bridgeID := createTestBridgeWithToken(t, "fake-token", "preview_bot")

	// Sign with a platform that doesn't match the bridge row's type.
	ts, sig := signAuthExternal("slack", bridgeID.String(), "1")
	url := fmt.Sprintf("/api/v1/link-identity/preview?platform=slack&bridge=%s&uid=1&ts=%s&sig=%s",
		bridgeID, ts, sig)

	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/link-identity/preview", ih.LinkIdentityPreview)
	})
	req := userRequestJSON(t, "GET", url, userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("mismatch: status = %d, want 400", rec.Code)
	}
}
