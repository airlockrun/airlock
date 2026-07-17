package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildAuthURLRejectsReservedParams(t *testing.T) {
	reserved := []string{"client_id", "redirect_uri", "state", "response_type", "code_challenge", "code_challenge_method"}
	for _, key := range reserved {
		t.Run(key, func(t *testing.T) {
			client := NewClient(http.DefaultClient, false)
			_, err := client.BuildAuthURL("https://provider.example/authorize", "client", "https://airlock.example/callback", "state", "challenge", "scope", map[string]string{key: "attacker"})
			if err == nil {
				t.Fatalf("BuildAuthURL accepted reserved parameter %q", key)
			}
		})
	}
}

func TestBuildAuthURLRequiresHTTPSOutsideLocalhostDevelopment(t *testing.T) {
	client := NewClient(http.DefaultClient, false)
	if _, err := client.BuildAuthURL("http://localhost/authorize", "client", "https://airlock.example/callback", "state", "challenge", "scope", nil); err == nil {
		t.Fatal("BuildAuthURL accepted HTTP localhost without development mode")
	}
	client = NewClient(http.DefaultClient, true)
	if _, err := client.BuildAuthURL("http://localhost/authorize", "client", "http://localhost/callback", "state", "challenge", "scope", nil); err != nil {
		t.Fatalf("BuildAuthURL rejected localhost development URL: %v", err)
	}
}

func TestTokenRequestUsesClientSecretBasic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, secret, ok := r.BasicAuth()
		if !ok || clientID != "client" || secret != "secret" {
			t.Errorf("BasicAuth() = %q, %q, %v", clientID, secret, ok)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Form.Get("client_secret") != "" {
			t.Error("client_secret was sent in the request body")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer"}`))
	}))
	defer server.Close()

	_, err := NewClient(server.Client(), true).ExchangeCode(t.Context(), server.URL, "code", "verifier", "https://airlock.example/callback", "client", "secret")
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
}

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

	c := NewClient(srv.Client(), true)
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

	c := NewClient(srv.Client(), true)
	_, err := c.RefreshToken(context.Background(), srv.URL, "tok", "cid", "csec")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		t.Fatalf("did not expect *OAuthError, got %v", err)
	}
}
