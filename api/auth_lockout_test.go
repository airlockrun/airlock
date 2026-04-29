package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/auth/lockout"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const lockoutTestPassword = "correct-horse-battery-staple"

// fastLockoutPolicy keeps the lockout semantics but trims the padding so the
// suite doesn't sleep 400ms per failing request.
var fastLockoutPolicy = lockout.Policy{
	WindowMinutes: 15,
	Threshold:     10,
	TierDelays:    []time.Duration{5 * time.Minute, 15 * time.Minute, 60 * time.Minute},
	PadDuration:   1 * time.Millisecond,
}

func newLockoutAuthHandler(t *testing.T) *AuthHandler {
	t.Helper()
	return &AuthHandler{
		db:            testDB,
		jwtSecret:     "test-secret-key-for-auth-lockout",
		logger:        zap.NewNop(),
		lockoutPolicy: fastLockoutPolicy,
	}
}

// seedLockoutUser inserts a user with a known bcrypt-hashed password.
// Returns the email so tests can drive the Login handler against it.
func seedLockoutUser(t *testing.T) string {
	t.Helper()
	hash, err := auth.HashPassword(lockoutTestPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	email := "lockout-" + uuid.New().String()[:8] + "@example.com"
	_, err = dbq.New(testDB.Pool()).CreateUser(context.Background(), dbq.CreateUserParams{
		Email:        email,
		DisplayName:  "Lockout Test",
		PasswordHash: hash,
		TenantRole:   "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return email
}

func loginAttempt(t *testing.T, h *AuthHandler, email, password, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := protoMarshal.Marshal(&airlockv1.LoginRequest{Email: email, Password: password})
	if err != nil {
		t.Fatalf("marshal LoginRequest: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	return rec
}

func TestLoginLockout_LocksAfterThreshold(t *testing.T) {
	skipIfNoDB(t)
	h := newLockoutAuthHandler(t)
	email := seedLockoutUser(t)
	const ip = "203.0.113.10:5555"

	for i := 1; i <= int(fastLockoutPolicy.Threshold); i++ {
		rec := loginAttempt(t, h, email, "wrong", ip)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d, want 401", i, rec.Code)
		}
	}
	// Threshold-th attempt has just installed the lockout; the *next* hit
	// short-circuits with 429.
	rec := loginAttempt(t, h, email, "wrong", ip)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("post-threshold: status=%d, want 429", rec.Code)
	}
	retry := rec.Header().Get("Retry-After")
	if retry == "" {
		t.Fatal("Retry-After header missing on 429")
	}
	if n, err := strconv.Atoi(retry); err != nil || n < 1 {
		t.Fatalf("Retry-After %q is not a positive int", retry)
	}
}

func TestLoginLockout_PerEmailIPKeying(t *testing.T) {
	skipIfNoDB(t)
	h := newLockoutAuthHandler(t)
	email := seedLockoutUser(t)
	const attackerIP = "198.51.100.7:1111"
	const victimIP = "203.0.113.99:2222"

	// Attacker exhausts the threshold.
	for i := 0; i < int(fastLockoutPolicy.Threshold); i++ {
		_ = loginAttempt(t, h, email, "wrong", attackerIP)
	}
	if rec := loginAttempt(t, h, email, "wrong", attackerIP); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker IP not locked out: status=%d", rec.Code)
	}

	// Legit user from a different IP must not be impacted.
	if rec := loginAttempt(t, h, email, "wrong", victimIP); rec.Code != http.StatusUnauthorized {
		t.Fatalf("victim IP unexpectedly affected: status=%d, want 401", rec.Code)
	}
	if rec := loginAttempt(t, h, email, lockoutTestPassword, victimIP); rec.Code != http.StatusOK {
		t.Fatalf("victim IP success login failed: status=%d", rec.Code)
	}
}

func TestLoginLockout_SuccessClearsCounter(t *testing.T) {
	skipIfNoDB(t)
	h := newLockoutAuthHandler(t)
	email := seedLockoutUser(t)
	const ip = "203.0.113.50:3333"

	// Half-fill the counter.
	for i := 0; i < 5; i++ {
		_ = loginAttempt(t, h, email, "wrong", ip)
	}
	// Successful login wipes the bucket.
	if rec := loginAttempt(t, h, email, lockoutTestPassword, ip); rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d, want 200", rec.Code)
	}
	// Should now take a fresh threshold worth of failures to lock out.
	for i := 0; i < int(fastLockoutPolicy.Threshold); i++ {
		rec := loginAttempt(t, h, email, "wrong", ip)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("post-clear attempt %d: status=%d, want 401", i+1, rec.Code)
		}
	}
}

func TestLoginLockout_UnknownEmailStillCountsTowardLock(t *testing.T) {
	skipIfNoDB(t)
	h := newLockoutAuthHandler(t)
	const email = "ghost-" + "00000000@example.com"
	const ip = "203.0.113.77:4444"

	for i := 0; i < int(fastLockoutPolicy.Threshold); i++ {
		rec := loginAttempt(t, h, email, "wrong", ip)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unknown email attempt %d: status=%d, want 401", i+1, rec.Code)
		}
	}
	if rec := loginAttempt(t, h, email, "wrong", ip); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("unknown email post-threshold: status=%d, want 429", rec.Code)
	}
}
