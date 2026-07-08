package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func TestUserSessionRefreshAndLogout(t *testing.T) {
	skipIfNoDB(t)
	h := NewAuthHandler(testDB, testJWTSecret, "", zap.NewNop())
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
	if loginResp.RefreshToken == "" {
		t.Fatal("login did not return refresh token")
	}

	refreshBody, err := protoMarshal.Marshal(&airlockv1.RefreshRequest{RefreshToken: loginResp.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	refreshRec := httptest.NewRecorder()
	h.Refresh(refreshRec, httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(refreshBody)))
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refreshRec.Code, refreshRec.Body.String())
	}

	logoutBody, err := protoMarshal.Marshal(&airlockv1.LogoutRequest{RefreshToken: loginResp.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	logoutRec := httptest.NewRecorder()
	h.Logout(logoutRec, httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewReader(logoutBody)))
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d body=%s", logoutRec.Code, logoutRec.Body.String())
	}

	refreshRec = httptest.NewRecorder()
	h.Refresh(refreshRec, httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(refreshBody)))
	if refreshRec.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout status=%d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
}
