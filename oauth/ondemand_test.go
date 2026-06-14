package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/airlockrun/airlock/secrets"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// identityStore is an in-test secrets.Store that doesn't encrypt: Get echoes
// the stored value, Put echoes the plaintext. Only Get/Put are exercised by
// resolveToken; the embedded nil interface covers the rest of the surface.
type identityStore struct{ secrets.Store }

func (identityStore) Get(_ context.Context, _, stored string) (string, error) { return stored, nil }
func (identityStore) Put(_ context.Context, _, plaintext string) (string, error) {
	return plaintext, nil
}

func tsTime(d time.Duration) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Now().Add(d), Valid: true}
}

func baseRow(tokenURL string, expiresAt pgtype.Timestamptz, refreshRef string) tokenRow {
	return tokenRow{
		refPrefix:    "connection",
		accessRef:    "access-cipher",
		refreshRef:   refreshRef,
		clientIDRef:  "cid",
		clientSecRef: "csec",
		tokenURL:     tokenURL,
		expiresAt:    expiresAt,
	}
}

func TestResolveToken_NoAccessToken_NeedsReauth(t *testing.T) {
	row := baseRow("", tsTime(time.Hour), "refresh-cipher")
	row.accessRef = ""
	_, persist, err := resolveToken(context.Background(), identityStore{}, NewClient(), zap.NewNop(), row, time.Now(), failUpdate(t), failClear(t))
	if !errors.Is(err, ErrNeedsReauth) {
		t.Fatalf("err = %v, want ErrNeedsReauth", err)
	}
	if persist {
		t.Error("persist = true, want false (read-only)")
	}
}

func TestResolveToken_Valid_ReturnsCurrent(t *testing.T) {
	row := baseRow("", tsTime(time.Hour), "refresh-cipher")
	tok, persist, err := resolveToken(context.Background(), identityStore{}, NewClient(), zap.NewNop(), row, time.Now(), failUpdate(t), failClear(t))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tok != "access-cipher" {
		t.Errorf("token = %q, want access-cipher (current, undecrypted by identity store)", tok)
	}
	if persist {
		t.Error("persist = true, want false (no refresh happened)")
	}
}

func TestResolveToken_Expired_NoRefreshToken_NeedsReauth(t *testing.T) {
	row := baseRow("", tsTime(-time.Minute), "")
	_, persist, err := resolveToken(context.Background(), identityStore{}, NewClient(), zap.NewNop(), row, time.Now(), failUpdate(t), failClear(t))
	if !errors.Is(err, ErrNeedsReauth) {
		t.Fatalf("err = %v, want ErrNeedsReauth", err)
	}
	if persist {
		t.Error("persist = true, want false")
	}
}

func TestResolveToken_Expired_RefreshSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`))
	}))
	defer srv.Close()

	var gotAccess, gotRefresh string
	update := func(_ context.Context, accessRef string, _ pgtype.Timestamptz, refreshRef string) error {
		gotAccess, gotRefresh = accessRef, refreshRef
		return nil
	}

	row := baseRow(srv.URL, tsTime(-time.Minute), "old-refresh")
	tok, persist, err := resolveToken(context.Background(), identityStore{}, NewClient(), zap.NewNop(), row, time.Now(), update, failClear(t))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !persist {
		t.Error("persist = false, want true (refreshed → must commit)")
	}
	if tok != "new-access" {
		t.Errorf("token = %q, want new-access", tok)
	}
	if gotAccess != "new-access" {
		t.Errorf("persisted access = %q, want new-access", gotAccess)
	}
	if gotRefresh != "new-refresh" {
		t.Errorf("persisted refresh = %q, want new-refresh (provider rotated)", gotRefresh)
	}
}

func TestResolveToken_Expired_RefreshKeepsOldRefreshToken(t *testing.T) {
	// Provider returns no refresh_token → keep the existing one (Spotify
	// confidential flow doesn't rotate).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"new-access","expires_in":3600}`))
	}))
	defer srv.Close()

	var gotRefresh string
	update := func(_ context.Context, _ string, _ pgtype.Timestamptz, refreshRef string) error {
		gotRefresh = refreshRef
		return nil
	}
	row := baseRow(srv.URL, tsTime(-time.Minute), "old-refresh")
	if _, _, err := resolveToken(context.Background(), identityStore{}, NewClient(), zap.NewNop(), row, time.Now(), update, failClear(t)); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if gotRefresh != "old-refresh" {
		t.Errorf("persisted refresh = %q, want old-refresh (unchanged)", gotRefresh)
	}
}

func TestResolveToken_Expired_InvalidGrant_ClearsAndNeedsReauth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"revoked"}`))
	}))
	defer srv.Close()

	cleared := false
	clear := func(_ context.Context) error { cleared = true; return nil }

	row := baseRow(srv.URL, tsTime(-time.Minute), "old-refresh")
	_, persist, err := resolveToken(context.Background(), identityStore{}, NewClient(), zap.NewNop(), row, time.Now(), failUpdate(t), clear)
	if !errors.Is(err, ErrNeedsReauth) {
		t.Fatalf("err = %v, want ErrNeedsReauth", err)
	}
	if !cleared {
		t.Error("clear not called on invalid_grant")
	}
	if !persist {
		t.Error("persist = false, want true (clear write must commit)")
	}
}

func TestResolveToken_Expired_TransientError_NotReauth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	}))
	defer srv.Close()

	row := baseRow(srv.URL, tsTime(-time.Minute), "old-refresh")
	_, persist, err := resolveToken(context.Background(), identityStore{}, NewClient(), zap.NewNop(), row, time.Now(), failUpdate(t), failClear(t))
	if err == nil {
		t.Fatal("expected a transient error")
	}
	if errors.Is(err, ErrNeedsReauth) {
		t.Error("transient failure must not be ErrNeedsReauth (don't nudge re-auth)")
	}
	if persist {
		t.Error("persist = true, want false (nothing written on transient failure)")
	}
}

func failUpdate(t *testing.T) func(context.Context, string, pgtype.Timestamptz, string) error {
	return func(context.Context, string, pgtype.Timestamptz, string) error {
		t.Helper()
		t.Error("update called unexpectedly")
		return nil
	}
}

func failClear(t *testing.T) func(context.Context) error {
	return func(context.Context) error {
		t.Helper()
		t.Error("clear called unexpectedly")
		return nil
	}
}
