package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
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
	if inspect.Status != "pending" || inspect.UserCode != begin.UserCode || inspect.DeviceName != "dev@workstation" {
		t.Fatalf("inspect = %#v", inspect)
	}

	approved := deviceLoginApprove(t, h, user, begin.UserCode)
	if approved.Status != "approved" {
		t.Fatalf("approved status = %q", approved.Status)
	}
	approvedRow, err := dbq.New(testDB.Pool()).GetDeviceLoginByUserCodeHash(context.Background(), hashDeviceLoginCode(normalizeUserCode(begin.UserCode)))
	if err != nil {
		t.Fatalf("GetDeviceLoginByUserCodeHash: %v", err)
	}
	if !approvedRow.ApprovedAuthEpoch.Valid || approvedRow.ApprovedAuthEpoch.Int64 != 0 {
		t.Fatalf("approved_auth_epoch = %#v, want 0", approvedRow.ApprovedAuthEpoch)
	}

	poll := deviceLoginPoll(t, h, begin.DeviceCode)
	if poll.Status != "approved" || poll.AccessToken == "" || poll.RefreshToken == "" || poll.User.GetEmail() == "" {
		t.Fatalf("poll approved = %#v", poll)
	}
	sessions, err := dbq.New(testDB.Pool()).ListUserSessionsByUser(context.Background(), toPgUUID(user))
	if err != nil {
		t.Fatalf("ListUserSessionsByUser: %v", err)
	}
	if len(sessions) != 1 || sessions[0].Kind != userSessionKindCLI || sessions[0].DeviceName != "dev@workstation" {
		t.Fatalf("sessions = %#v", sessions)
	}

	poll = deviceLoginPoll(t, h, begin.DeviceCode)
	if poll.Status == "approved" {
		t.Fatalf("device login was consumed more than once: %#v", poll)
	}
}

func TestDeviceLoginCredentialRecoveryInvalidatesApproval(t *testing.T) {
	skipIfNoDB(t)
	h := newDeviceLoginHandler(testDB, testJWTSecret, "https://airlock.example.com")
	user := seedDeviceLoginUser(t)
	begin := deviceLoginBegin(t, h)
	deviceLoginApprove(t, h, user, begin.UserCode)

	if err := dbq.New(testDB.Pool()).SetTempPassword(context.Background(), dbq.SetTempPasswordParams{
		PasswordHash: pgtype.Text{String: "recovered", Valid: true},
		ID:           toPgUUID(user),
	}); err != nil {
		t.Fatalf("SetTempPassword: %v", err)
	}
	poll := deviceLoginPoll(t, h, begin.DeviceCode)
	if poll.Status != "expired" || poll.AccessToken != "" || poll.RefreshToken != "" {
		t.Fatalf("poll after credential recovery = %#v", poll)
	}
	sessions, err := dbq.New(testDB.Pool()).ListUserSessionsByUser(context.Background(), toPgUUID(user))
	if err != nil {
		t.Fatalf("ListUserSessionsByUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("credential recovery handoff created sessions: %#v", sessions)
	}
}

func TestDeviceLoginRecoveryWinsBlockedPollRace(t *testing.T) {
	skipIfNoDB(t)
	h := newDeviceLoginHandler(testDB, testJWTSecret, "https://airlock.example.com")
	user := seedDeviceLoginUser(t)
	begin := deviceLoginBegin(t, h)
	deviceLoginApprove(t, h, user, begin.UserCode)

	tx, err := testDB.Pool().Begin(context.Background())
	if err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	defer tx.Rollback(context.Background())
	if err := dbq.New(tx).SetTempPassword(context.Background(), dbq.SetTempPasswordParams{
		PasswordHash: pgtype.Text{String: "recovered", Valid: true},
		ID:           toPgUUID(user),
	}); err != nil {
		t.Fatalf("SetTempPassword: %v", err)
	}

	body, err := protoMarshal.Marshal(&airlockv1.DeviceLoginPollRequest{DeviceCode: begin.DeviceCode})
	if err != nil {
		t.Fatalf("marshal poll: %v", err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.Poll(rec, httptest.NewRequest(http.MethodPost, "/auth/device/poll", bytes.NewReader(body)))
		result <- rec
	}()
	// The poll claims the device row, then blocks acquiring the user row held
	// by credential recovery. Committing makes the advanced epoch visible to
	// the consume query's locked recheck.
	time.Sleep(100 * time.Millisecond)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit recovery: %v", err)
	}
	rec := <-result
	if rec.Code != http.StatusOK {
		t.Fatalf("racing poll status=%d body=%s", rec.Code, rec.Body.String())
	}
	var poll airlockv1.DeviceLoginPollResponse
	decodeProtoResp(t, rec, &poll)
	if poll.Status != "expired" || poll.AccessToken != "" || poll.RefreshToken != "" {
		t.Fatalf("racing poll after recovery = %#v", &poll)
	}
}

func TestDeviceLoginConcurrentPollSingleWinner(t *testing.T) {
	skipIfNoDB(t)
	h := newDeviceLoginHandler(testDB, testJWTSecret, "https://airlock.example.com")
	user := seedDeviceLoginUser(t)
	begin := deviceLoginBegin(t, h)
	deviceLoginApprove(t, h, user, begin.UserCode)
	body, err := protoMarshal.Marshal(&airlockv1.DeviceLoginPollRequest{DeviceCode: begin.DeviceCode})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	recorders := make([]*httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := range recorders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			recorders[i] = httptest.NewRecorder()
			h.Poll(recorders[i], httptest.NewRequest(http.MethodPost, "/auth/device/poll", bytes.NewReader(body)))
		}(i)
	}
	close(start)
	wg.Wait()

	statuses := map[string]int{}
	for _, rec := range recorders {
		if rec.Code != http.StatusOK {
			t.Fatalf("poll status=%d body=%s", rec.Code, rec.Body.String())
		}
		var response airlockv1.DeviceLoginPollResponse
		decodeProtoResp(t, rec, &response)
		statuses[response.Status]++
	}
	if statuses["approved"] != 1 || statuses["slow_down"] != 1 {
		t.Fatalf("poll statuses = %v", statuses)
	}
	sessions, err := dbq.New(testDB.Pool()).ListUserSessionsByUser(context.Background(), toPgUUID(user))
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions=%#v err=%v", sessions, err)
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
	body, err := protoMarshal.Marshal(&airlockv1.DeviceLoginBeginRequest{ClientName: "air CLI", DeviceName: "dev@workstation"})
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
