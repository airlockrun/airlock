package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func TestUserSessionRefreshAndLogout(t *testing.T) {
	skipIfNoDB(t)
	h := NewAuthHandler(testDB, testJWTSecret, "", "http://localhost", zap.NewNop())
	password := "correct horse battery staple"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	email := "session-" + uuid.New().String()[:8] + "@example.com"
	_, err = dbq.New(testDB.Pool()).CreateUser(context.Background(), dbq.CreateUserParams{
		Email:        email,
		DisplayName:  "Session User",
		PasswordHash: pgtype.Text{String: hash, Valid: true},
		TenantRole:   "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	loginReq := &airlockv1.LoginRequest{Email: email, Password: password}

	loginBody, err := protoMarshal.Marshal(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	loginRec := httptest.NewRecorder()
	h.Login(loginRec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody)))
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp airlockv1.LoginResponse
	decodeProtoResp(t, loginRec, &loginResp)
	if loginResp.RefreshToken != "" {
		t.Fatal("browser login exposed refresh token in response")
	}
	var refreshCookie *http.Cookie
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == refreshCookieName {
			refreshCookie = cookie
		}
	}
	if refreshCookie == nil || !refreshCookie.HttpOnly || refreshCookie.Path != "/auth" {
		t.Fatalf("refresh cookie = %#v", refreshCookie)
	}

	refreshBody, err := protoMarshal.Marshal(&airlockv1.RefreshRequest{})
	if err != nil {
		t.Fatal(err)
	}
	badOriginReq := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(refreshBody))
	badOriginReq.Header.Set("Origin", "http://evil.example")
	badOriginReq.AddCookie(refreshCookie)
	badOriginRec := httptest.NewRecorder()
	h.Refresh(badOriginRec, badOriginReq)
	if badOriginRec.Code != http.StatusForbidden {
		t.Fatalf("bad-origin refresh status=%d body=%s", badOriginRec.Code, badOriginRec.Body.String())
	}
	refreshRec := httptest.NewRecorder()
	refreshReq := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(refreshBody))
	refreshReq.Header.Set("Origin", "http://localhost")
	refreshReq.AddCookie(refreshCookie)
	h.Refresh(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshResp airlockv1.RefreshResponse
	decodeProtoResp(t, refreshRec, &refreshResp)
	if refreshResp.RefreshToken != "" {
		t.Fatal("browser refresh exposed refresh token in response")
	}
	rotatedCookie := cookieByName(refreshRec.Result().Cookies(), refreshCookieName)
	if rotatedCookie == nil || rotatedCookie.Value == refreshCookie.Value {
		t.Fatalf("rotated refresh cookie = %#v", rotatedCookie)
	}

	staleRec := httptest.NewRecorder()
	staleReq := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(refreshBody))
	staleReq.Header.Set("Origin", "http://localhost")
	staleReq.AddCookie(refreshCookie)
	h.Refresh(staleRec, staleReq)
	if staleRec.Code != http.StatusUnauthorized {
		t.Fatalf("old refresh token status=%d body=%s", staleRec.Code, staleRec.Body.String())
	}

	logoutBody, err := protoMarshal.Marshal(&airlockv1.LogoutRequest{})
	if err != nil {
		t.Fatal(err)
	}
	badLogoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(logoutBody))
	badLogoutReq.Header.Set("Origin", "http://evil.example")
	badLogoutReq.AddCookie(refreshCookie)
	badLogoutRec := httptest.NewRecorder()
	h.Logout(badLogoutRec, badLogoutReq)
	if badLogoutRec.Code != http.StatusForbidden {
		t.Fatalf("bad-origin logout status=%d body=%s", badLogoutRec.Code, badLogoutRec.Body.String())
	}
	logoutRec := httptest.NewRecorder()
	logoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(logoutBody))
	logoutReq.Header.Set("Origin", "http://localhost")
	logoutReq.AddCookie(rotatedCookie)
	h.Logout(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d body=%s", logoutRec.Code, logoutRec.Body.String())
	}
	cookies := logoutRec.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != accessCookieName || cookies[0].MaxAge >= 0 || cookies[1].Name != refreshCookieName || cookies[1].MaxAge >= 0 {
		t.Fatalf("logout cookies = %#v", cookies)
	}

	refreshRec = httptest.NewRecorder()
	refreshReq = httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(refreshBody))
	refreshReq.Header.Set("Origin", "http://localhost")
	refreshReq.AddCookie(rotatedCookie)
	h.Refresh(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout status=%d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
}

func TestLogoutInvalidatesSubdomainSession(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	user, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "subdomain-logout-" + uuid.NewString() + "@example.com",
		DisplayName: "Subdomain Logout",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	accessToken, refreshToken, err := issueUserSessionTokens(ctx, testDB, testJWTSecret, user, userSessionKindCLI, cliClientName, "logout test")
	if err != nil {
		t.Fatalf("issueUserSessionTokens: %v", err)
	}
	accessClaims, err := auth.ValidateUserAccessToken(testJWTSecret, accessToken)
	if err != nil {
		t.Fatalf("ValidateUserAccessToken: %v", err)
	}
	agentID := uuid.New()
	subdomainToken, err := auth.IssueSubdomainToken(testJWTSecret, agentID, pgUUID(user.ID), uuid.MustParse(accessClaims.SessionID), user.Email, user.DisplayName, user.TenantRole, user.AuthEpoch)
	if err != nil {
		t.Fatalf("IssueSubdomainToken: %v", err)
	}
	subdomainReq := httptest.NewRequest(http.MethodGet, "https://agent.example.test/private", nil)
	subdomainReq.AddCookie(&http.Cookie{Name: relayCookieName, Value: subdomainToken})
	if _, ok, _ := validateSubdomainAuth(subdomainReq, q, testJWTSecret, agentID); !ok {
		t.Fatal("subdomain session was not initially valid")
	}

	body, err := protoMarshal.Marshal(&airlockv1.LogoutRequest{RefreshToken: refreshToken})
	if err != nil {
		t.Fatalf("marshal logout: %v", err)
	}
	rec := httptest.NewRecorder()
	NewAuthHandler(testDB, testJWTSecret, "", "http://localhost", zap.NewNop()).Logout(rec, httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(body)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok, _ := validateSubdomainAuth(subdomainReq, q, testJWTSecret, agentID); ok {
		t.Fatal("subdomain session survived logout")
	}
}

func TestWebRefreshRotationIsAtomic(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	user, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "rotate-" + uuid.NewString() + "@example.com",
		DisplayName: "Rotate User",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, refreshToken, err := issueUserSessionTokens(ctx, testDB, testJWTSecret, user, userSessionKindWeb, webClientName, "test")
	if err != nil {
		t.Fatal(err)
	}
	h := NewAuthHandler(testDB, testJWTSecret, "", "http://localhost", zap.NewNop())
	body, err := protoMarshal.Marshal(&airlockv1.RefreshRequest{})
	if err != nil {
		t.Fatal(err)
	}

	recorders := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
	var wg sync.WaitGroup
	for _, rec := range recorders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(body))
			req.Header.Set("Origin", "http://localhost")
			req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: refreshToken})
			h.Refresh(rec, req)
		}()
	}
	wg.Wait()

	var replacement *http.Cookie
	statuses := map[int]int{}
	for _, rec := range recorders {
		statuses[rec.Code]++
		if rec.Code == http.StatusOK {
			replacement = cookieByName(rec.Result().Cookies(), refreshCookieName)
		}
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusUnauthorized] != 1 {
		t.Fatalf("refresh statuses = %#v", statuses)
	}
	if replacement == nil || replacement.Value == refreshToken {
		t.Fatalf("replacement cookie = %#v", replacement)
	}
}

func TestCLIRefreshRotationIsAtomic(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	user, err := dbq.New(testDB.Pool()).CreateUser(ctx, dbq.CreateUserParams{
		Email:       "cli-refresh-" + uuid.NewString() + "@example.com",
		DisplayName: "CLI User",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, refreshToken, err := issueUserSessionTokens(ctx, testDB, testJWTSecret, user, userSessionKindCLI, cliClientName, "test")
	if err != nil {
		t.Fatal(err)
	}
	h := NewAuthHandler(testDB, testJWTSecret, "", "http://localhost", zap.NewNop())
	body, err := protoMarshal.Marshal(&airlockv1.RefreshRequest{RefreshToken: refreshToken})
	if err != nil {
		t.Fatal(err)
	}
	recorders := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
	var wg sync.WaitGroup
	for _, rec := range recorders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.Refresh(rec, httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(body)))
		}()
	}
	wg.Wait()

	statuses := map[int]int{}
	var replacement string
	for _, rec := range recorders {
		statuses[rec.Code]++
		if rec.Code != http.StatusOK {
			continue
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatalf("CLI refresh set browser cookies: %#v", rec.Result().Cookies())
		}
		var resp airlockv1.RefreshResponse
		decodeProtoResp(t, rec, &resp)
		if resp.AccessToken == "" || resp.RefreshToken == "" || resp.RefreshToken == refreshToken {
			t.Fatalf("CLI refresh response = %#v", &resp)
		}
		replacement = resp.RefreshToken
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusUnauthorized] != 1 {
		t.Fatalf("refresh statuses = %#v", statuses)
	}

	nextBody, err := protoMarshal.Marshal(&airlockv1.RefreshRequest{RefreshToken: replacement})
	if err != nil {
		t.Fatal(err)
	}
	nextRec := httptest.NewRecorder()
	h.Refresh(nextRec, httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(nextBody)))
	if nextRec.Code != http.StatusOK {
		t.Fatalf("replacement refresh status=%d body=%s", nextRec.Code, nextRec.Body.String())
	}
}

func TestLogoutReportsRevocationFailure(t *testing.T) {
	skipIfNoDB(t)
	brokenDB := db.New(context.Background(), testURL)
	brokenDB.Close()
	h := NewAuthHandler(brokenDB, testJWTSecret, "", "http://localhost", zap.NewNop())
	body, err := protoMarshal.Marshal(&airlockv1.LogoutRequest{RefreshToken: "opaque-token"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.Logout(rec, httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("logout cleared cookies after failed revocation: %#v", rec.Result().Cookies())
	}
}

func TestLiveSessionInvalidation(t *testing.T) {
	skipIfNoDB(t)
	q := dbq.New(testDB.Pool())
	ctx := context.Background()
	newSession := func(t *testing.T) (dbq.User, string) {
		t.Helper()
		user, err := q.CreateUser(ctx, dbq.CreateUserParams{
			Email:       "invalidation-" + uuid.NewString() + "@example.com",
			DisplayName: "Invalidation User",
			TenantRole:  "user",
		})
		if err != nil {
			t.Fatal(err)
		}
		access, _, err := issueUserSessionTokens(ctx, testDB, testJWTSecret, user, userSessionKindWeb, webClientName, "test")
		if err != nil {
			t.Fatal(err)
		}
		return user, access
	}
	status := func(token string) int {
		handler := auth.Middleware(testJWTSecret)(auth.LiveSessionMiddleware(testDB)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("role change", func(t *testing.T) {
		user, token := newSession(t)
		if got := status(token); got != http.StatusNoContent {
			t.Fatalf("before role change status=%d", got)
		}
		if err := q.UpdateUserRole(ctx, dbq.UpdateUserRoleParams{ID: user.ID, TenantRole: "manager"}); err != nil {
			t.Fatal(err)
		}
		if got := status(token); got != http.StatusUnauthorized {
			t.Fatalf("after role change status=%d", got)
		}
	})

	t.Run("session revoke", func(t *testing.T) {
		user, token := newSession(t)
		claims, err := auth.ValidateUserAccessToken(testJWTSecret, token)
		if err != nil {
			t.Fatal(err)
		}
		sessionID := uuid.MustParse(claims.SessionID)
		if _, err := q.RevokeUserSessionByID(ctx, dbq.RevokeUserSessionByIDParams{ID: toPgUUID(sessionID), UserID: user.ID}); err != nil {
			t.Fatal(err)
		}
		if got := status(token); got != http.StatusUnauthorized {
			t.Fatalf("after revoke status=%d", got)
		}
	})

	t.Run("password reset", func(t *testing.T) {
		user, token := newSession(t)
		if err := q.SetTempPassword(ctx, dbq.SetTempPasswordParams{PasswordHash: pgtype.Text{String: "reset", Valid: true}, ID: user.ID}); err != nil {
			t.Fatal(err)
		}
		if got := status(token); got != http.StatusUnauthorized {
			t.Fatalf("after reset status=%d", got)
		}
	})

	t.Run("user delete", func(t *testing.T) {
		user, token := newSession(t)
		if err := q.DeleteUser(ctx, user.ID); err != nil {
			t.Fatal(err)
		}
		if got := status(token); got != http.StatusUnauthorized {
			t.Fatalf("after delete status=%d", got)
		}
	})
}
