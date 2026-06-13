package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTokenRequest_InvalidGrantOn400 verifies that a 400 response
// carrying an RFC 6749 §5.2 error body produces a typed *OAuthError
// (so refresh.go's errors.As(err, &oauthErr) check fires and the
// credentials get cleared). Without this, Spotify's "Refresh token
// revoked" response would surface as an opaque
// `token request failed with status 400` and leave access_token_ref
// populated — the UI would keep showing the connection as authorized
// even though every refresh attempt is failing.
func TestTokenRequest_InvalidGrantOn400(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Refresh token revoked"}`))
	}))
	defer srv.Close()

	c := NewClient()
	_, err := c.RefreshToken(context.Background(), srv.URL, "tok", "cid", "csec")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.Code != "invalid_grant" {
		t.Errorf("Code = %q, want invalid_grant", oauthErr.Code)
	}
	if oauthErr.Description == "" {
		t.Error("Description should be populated")
	}
}

// TestTokenRequest_OpaqueErrorOnNon200WithoutOAuthBody verifies the
// fallback path: a non-200 with a body that isn't an RFC 6749 error
// envelope still surfaces with status info — we don't accidentally
// turn random 500s / HTML error pages into typed *OAuthError.
func TestTokenRequest_OpaqueErrorOnNon200WithoutOAuthBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream broke"))
	}))
	defer srv.Close()

	c := NewClient()
	_, err := c.RefreshToken(context.Background(), srv.URL, "tok", "cid", "csec")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		t.Fatalf("did not expect *OAuthError, got %v", err)
	}
}
