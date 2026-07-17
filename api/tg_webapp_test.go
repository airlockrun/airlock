package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestRelayStubSetsTargetNonceBeforeApexRedirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://demo.agents.test/private?tab=one", nil)
	req.RequestURI = "/private?tab=one"
	rec := httptest.NewRecorder()
	renderTGWebAppStub(rec, req, "https://airlock.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	cookie := cookieByName(rec.Result().Cookies(), relayNonceName)
	if cookie == nil || cookie.Value == "" || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" {
		t.Fatalf("relay nonce cookie = %#v", cookie)
	}

	match := regexp.MustCompile(`var fallback = "([^"]+)"`).FindStringSubmatch(rec.Body.String())
	if len(match) != 2 {
		t.Fatalf("fallback URL not found in stub")
	}
	fallback, err := url.Parse(match[1])
	if err != nil {
		t.Fatalf("parse fallback: %v", err)
	}
	if fallback.Query().Get("nonce") != cookie.Value {
		t.Fatal("fallback nonce does not match target-host cookie")
	}
	if fallback.Query().Get("return") != "https://demo.agents.test/private?tab=one" {
		t.Errorf("return = %q", fallback.Query().Get("return"))
	}
}

func TestTelegramAuthCreatesBoundedRevocableSession(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	user, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "telegram-" + uuid.NewString() + "@example.com",
		DisplayName: "Telegram User",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	agentID := uuid.New()
	token, err := issueTelegramSubdomainSession(ctx, testDB, testJWTSecret, agentID, user.ID)
	if err != nil {
		t.Fatalf("issueTelegramSubdomainSession: %v", err)
	}
	claims, err := auth.ValidateSubdomainToken(testJWTSecret, token, agentID)
	if err != nil {
		t.Fatalf("ValidateSubdomainToken: %v", err)
	}
	sessionID := uuid.MustParse(claims.SessionID)
	sessions, err := q.ListUserSessionsByUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserSessionsByUser: %v", err)
	}
	if len(sessions) != 1 || pgUUID(sessions[0].ID) != sessionID || sessions[0].Kind != userSessionKindTelegram {
		t.Fatalf("Telegram sessions = %#v", sessions)
	}
	if sessions[0].RefreshTokenHash != nil {
		t.Fatal("Telegram session has a refresh credential")
	}
	if ttl := time.Until(sessions[0].ExpiresAt.Time); ttl < 55*time.Minute || ttl > 65*time.Minute {
		t.Fatalf("Telegram session TTL = %v, want about one hour", ttl)
	}
	if _, err := auth.ResolveLiveUserClaims(ctx, q, claims, true); err != nil {
		t.Fatalf("ResolveLiveUserClaims before revoke: %v", err)
	}
	if rows, err := q.RevokeUserSessionByID(ctx, dbq.RevokeUserSessionByIDParams{ID: sessions[0].ID, UserID: user.ID}); err != nil || rows != 1 {
		t.Fatalf("RevokeUserSessionByID = (%d, %v)", rows, err)
	}
	if _, err := auth.ResolveLiveUserClaims(ctx, q, claims, true); err == nil {
		t.Fatal("Telegram subdomain token survived session revoke")
	}
}

func TestTGWebAppAuthRequiresTargetOriginAndJSON(t *testing.T) {
	tests := []struct {
		name        string
		origin      string
		contentType string
		want        int
	}{
		{name: "missing origin", contentType: "application/json", want: http.StatusForbidden},
		{name: "wrong origin", origin: "https://evil.test", contentType: "application/json", want: http.StatusForbidden},
		{name: "missing content type", origin: "https://demo.agents.test", want: http.StatusUnsupportedMediaType},
		{name: "form content type", origin: "https://demo.agents.test", contentType: "application/x-www-form-urlencoded", want: http.StatusUnsupportedMediaType},
		{name: "same origin JSON", origin: "https://demo.agents.test", contentType: "application/json", want: http.StatusBadRequest},
		{name: "same origin JSON charset", origin: "https://demo.agents.test", contentType: "application/json; charset=utf-8", want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://demo.agents.test/__air/tg/auth", strings.NewReader("{"))
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Content-Type", tt.contentType)
			rec := httptest.NewRecorder()
			handleTGWebAppAuth(context.Background(), rec, req, testJWTSecret, uuid.Nil, nil, nil, zap.NewNop())
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d; body=%s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}
