package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverUpstream(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ProtectedResourceMeta{
			Resource:             "https://mcp.example.com",
			AuthorizationServers: []string{"https://auth.example.com"},
			ScopesSupported:      []string{"read", "write"},
		})
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(AuthServerMeta{
			Issuer:                        "https://auth.example.com",
			AuthorizationEndpoint:         "https://auth.example.com/authorize",
			TokenEndpoint:                 "https://auth.example.com/token",
			RegistrationEndpoint:          "https://auth.example.com/register",
			CodeChallengeMethodsSupported: []string{"S256"},
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// DiscoverUpstream expects the auth server URL to match, but in tests the
	// protected resource metadata points to https://auth.example.com which
	// won't resolve. Instead, test the individual functions with the test server.

	ctx := context.Background()

	t.Run("DiscoverProtectedResource", func(t *testing.T) {
		meta, err := DiscoverProtectedResource(ctx, ts.Client(), ts.URL+"/mcp")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Resource != "https://mcp.example.com" {
			t.Errorf("resource = %q, want https://mcp.example.com", meta.Resource)
		}
		if len(meta.AuthorizationServers) != 1 {
			t.Fatalf("expected 1 auth server, got %d", len(meta.AuthorizationServers))
		}
		if len(meta.ScopesSupported) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(meta.ScopesSupported))
		}
	})

	t.Run("FetchAuthServerMetadata", func(t *testing.T) {
		meta, err := FetchAuthServerMetadata(ctx, ts.Client(), ts.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.AuthorizationEndpoint != "https://auth.example.com/authorize" {
			t.Errorf("authorization_endpoint = %q", meta.AuthorizationEndpoint)
		}
		if meta.TokenEndpoint != "https://auth.example.com/token" {
			t.Errorf("token_endpoint = %q", meta.TokenEndpoint)
		}
		if meta.RegistrationEndpoint != "https://auth.example.com/register" {
			t.Errorf("registration_endpoint = %q", meta.RegistrationEndpoint)
		}
	})

	t.Run("ValidatePKCESupport", func(t *testing.T) {
		tests := []struct {
			name    string
			methods []string
			wantErr bool
		}{
			{"S256 supported", []string{"S256"}, false},
			{"S256 among others", []string{"plain", "S256"}, false},
			{"not declared", nil, false},
			{"only plain", []string{"plain"}, true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidatePKCESupport(&AuthServerMeta{
					CodeChallengeMethodsSupported: tt.methods,
				})
				if (err != nil) != tt.wantErr {
					t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
				}
				if tt.wantErr && !errors.Is(err, ErrPKCENotSupported) {
					t.Errorf("expected ErrPKCENotSupported, got %v", err)
				}
			})
		}
	})

	t.Run("DiscoverProtectedResource_NotFound", func(t *testing.T) {
		emptyServer := httptest.NewServer(http.NotFoundHandler())
		defer emptyServer.Close()

		_, err := DiscoverProtectedResource(ctx, emptyServer.Client(), emptyServer.URL)
		if err == nil {
			t.Fatal("expected error for missing metadata")
		}
		if !errors.Is(err, ErrDiscoveryFailed) {
			t.Errorf("expected ErrDiscoveryFailed, got %v", err)
		}
	})

	t.Run("FetchAuthServerMetadata_OIDCFallback", func(t *testing.T) {
		oidcMux := http.NewServeMux()
		oidcMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(AuthServerMeta{
				Issuer:                "https://oidc.example.com",
				AuthorizationEndpoint: "https://oidc.example.com/authorize",
				TokenEndpoint:         "https://oidc.example.com/token",
			})
		})
		oidcServer := httptest.NewServer(oidcMux)
		defer oidcServer.Close()

		meta, err := FetchAuthServerMetadata(ctx, oidcServer.Client(), oidcServer.URL)
		if err != nil {
			t.Fatalf("OIDC fallback failed: %v", err)
		}
		if meta.AuthorizationEndpoint != "https://oidc.example.com/authorize" {
			t.Errorf("authorization_endpoint = %q", meta.AuthorizationEndpoint)
		}
	})

	t.Run("FullDiscoverUpstream", func(t *testing.T) {
		// Set up a server that hosts both resource metadata and auth server metadata.
		fullMux := http.NewServeMux()
		var serverURL string

		fullMux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(ProtectedResourceMeta{
				Resource:             serverURL,
				AuthorizationServers: []string{serverURL},
				ScopesSupported:      []string{"tools"},
			})
		})
		fullMux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(AuthServerMeta{
				Issuer:                        serverURL,
				AuthorizationEndpoint:         serverURL + "/authorize",
				TokenEndpoint:                 serverURL + "/token",
				CodeChallengeMethodsSupported: []string{"S256"},
			})
		})

		fullServer := httptest.NewServer(fullMux)
		defer fullServer.Close()
		serverURL = fullServer.URL

		result, err := DiscoverUpstream(ctx, fullServer.Client(), fullServer.URL)
		if err != nil {
			t.Fatalf("DiscoverUpstream failed: %v", err)
		}
		if result.AuthorizationURL != fullServer.URL+"/authorize" {
			t.Errorf("authorization_url = %q", result.AuthorizationURL)
		}
		if result.TokenURL != fullServer.URL+"/token" {
			t.Errorf("token_url = %q", result.TokenURL)
		}
		if len(result.ScopesSupported) != 1 || result.ScopesSupported[0] != "tools" {
			t.Errorf("scopes = %v", result.ScopesSupported)
		}
	})
}
