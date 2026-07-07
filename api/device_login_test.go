package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
)

func TestDeviceLoginFlow(t *testing.T) {
	skipIfNoDB(t)
	h := newDeviceLoginHandler(testDB, testJWTSecret, "https://airlock.example.com")
	user := seedDeviceLoginUser(t)

	begin := deviceLoginBegin(t, h)
	if begin.VerificationUrl != "https://airlock.example.com/device-login" {
		t.Fatalf("verification_url = %q", begin.VerificationUrl)
	}
	if strings.Contains(begin.VerificationUrl, begin.UserCode) {
		t.Fatalf("verification_url contains user code: %s", begin.VerificationUrl)
	}

	inspect := deviceLoginInspect(t, h, user, begin.UserCode)
	if inspect.Status != "pending" || inspect.UserCode != begin.UserCode {
		t.Fatalf("inspect = %#v", inspect)
	}

	approved := deviceLoginApprove(t, h, user, begin.UserCode)
	if approved.Status != "approved" {
		t.Fatalf("approved status = %q", approved.Status)
	}

	poll := deviceLoginPoll(t, h, begin.DeviceCode)
	if poll.Status != "approved" || poll.AccessToken == "" || poll.RefreshToken == "" || poll.User.GetEmail() == "" {
		t.Fatalf("poll approved = %#v", poll)
	}

	poll = deviceLoginPoll(t, h, begin.DeviceCode)
	if poll.Status == "approved" {
		t.Fatalf("device login was consumed more than once: %#v", poll)
	}
}

func seedDeviceLoginUser(t *testing.T) uuid.UUID {
	t.Helper()
	user, err := dbq.New(testDB.Pool()).CreateUser(context.Background(), dbq.CreateUserParams{
		Email:       "device-" + uuid.New().String()[:8] + "@example.com",
		DisplayName: "Device Login",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return pgUUID(user.ID)
}

func deviceLoginBegin(t *testing.T, h *deviceLoginHandler) *airlockv1.DeviceLoginBeginResponse {
	t.Helper()
	body, err := protoMarshal.Marshal(&airlockv1.DeviceLoginBeginRequest{ClientName: "air CLI"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/device/begin", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Begin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out airlockv1.DeviceLoginBeginResponse
	decodeProtoResp(t, rec, &out)
	return &out
}

func deviceLoginInspect(t *testing.T, h *deviceLoginHandler, user uuid.UUID, code string) *airlockv1.DeviceLoginInspectResponse {
	t.Helper()
	body, err := protoMarshal.Marshal(&airlockv1.DeviceLoginInspectRequest{UserCode: code})
	if err != nil {
		t.Fatal(err)
	}
	req := authedDeviceLoginRequest(t, user, http.MethodPost, "/api/v1/device-login/inspect", body)
	rec := httptest.NewRecorder()
	auth.Middleware(testJWTSecret)(http.HandlerFunc(h.Inspect)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inspect status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out airlockv1.DeviceLoginInspectResponse
	decodeProtoResp(t, rec, &out)
	return &out
}

func deviceLoginApprove(t *testing.T, h *deviceLoginHandler, user uuid.UUID, code string) *airlockv1.DeviceLoginInspectResponse {
	t.Helper()
	body, err := protoMarshal.Marshal(&airlockv1.DeviceLoginApproveRequest{UserCode: code})
	if err != nil {
		t.Fatal(err)
	}
	req := authedDeviceLoginRequest(t, user, http.MethodPost, "/api/v1/device-login/approve", body)
	rec := httptest.NewRecorder()
	auth.Middleware(testJWTSecret)(http.HandlerFunc(h.Approve)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out airlockv1.DeviceLoginInspectResponse
	decodeProtoResp(t, rec, &out)
	return &out
}

func deviceLoginPoll(t *testing.T, h *deviceLoginHandler, deviceCode string) *airlockv1.DeviceLoginPollResponse {
	t.Helper()
	body, err := protoMarshal.Marshal(&airlockv1.DeviceLoginPollRequest{DeviceCode: deviceCode})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/device/poll", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Poll(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("poll status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out airlockv1.DeviceLoginPollResponse
	decodeProtoResp(t, rec, &out)
	return &out
}

func authedDeviceLoginRequest(t *testing.T, user uuid.UUID, method, path string, body []byte) *http.Request {
	t.Helper()
	token, err := auth.IssueToken(testJWTSecret, user, "device@example.com", "Device Login", "user", false)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}
