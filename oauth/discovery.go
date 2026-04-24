package oauth

// OAuth discovery for MCP servers.
// Implements RFC 9728 (Protected Resource Metadata) and RFC 8414 (Authorization Server Metadata).
// Ported from gateway/internal/tokenbroker/discovery.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

var (
	// ErrDiscoveryFailed indicates that metadata discovery did not succeed.
	ErrDiscoveryFailed = errors.New("metadata discovery failed")

	// ErrPKCENotSupported indicates the authorization server does not support S256 PKCE.
	ErrPKCENotSupported = errors.New("authorization server does not support S256 PKCE")
)

// ProtectedResourceMeta represents RFC 9728 Protected Resource Metadata.
type ProtectedResourceMeta struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
}

// AuthServerMeta represents RFC 8414 Authorization Server Metadata.
type AuthServerMeta struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

// DiscoveryResult contains the result of upstream OAuth discovery.
type DiscoveryResult struct {
	ResourceURI          string
	AuthorizationURL     string
	TokenURL             string
	RegistrationEndpoint string // RFC 7591 dynamic client registration endpoint
	ScopesSupported      []string
}

// DiscoverProtectedResource fetches RFC 9728 Protected Resource Metadata.
// Tries /.well-known/oauth-protected-resource/{path} first, then falls back to root.
func DiscoverProtectedResource(ctx context.Context, httpClient *http.Client, serverURL string) (*ProtectedResourceMeta, error) {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}

	// Try path-aware well-known first: /.well-known/oauth-protected-resource/{path}
	path := strings.TrimRight(parsed.Path, "/")
	if path != "" && path != "/" {
		wellKnown := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource%s", parsed.Scheme, parsed.Host, path)
		meta, err := fetchJSON[ProtectedResourceMeta](ctx, httpClient, wellKnown)
		if err == nil {
			return meta, nil
		}
	}

	// Fall back to root: /.well-known/oauth-protected-resource
	wellKnown := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", parsed.Scheme, parsed.Host)
	meta, err := fetchJSON[ProtectedResourceMeta](ctx, httpClient, wellKnown)
	if err != nil {
		return nil, fmt.Errorf("%w: protected resource metadata not found at %s: %v", ErrDiscoveryFailed, serverURL, err)
	}

	return meta, nil
}

// FetchAuthServerMetadata fetches RFC 8414 Authorization Server Metadata.
// Tries /.well-known/oauth-authorization-server first, then falls back to /.well-known/openid-configuration.
func FetchAuthServerMetadata(ctx context.Context, httpClient *http.Client, authServerURL string) (*AuthServerMeta, error) {
	parsed, err := url.Parse(authServerURL)
	if err != nil {
		return nil, fmt.Errorf("parse auth server URL: %w", err)
	}

	// Try RFC 8414 path-aware: /.well-known/oauth-authorization-server/{path}
	path := strings.TrimRight(parsed.Path, "/")
	if path != "" && path != "/" {
		wellKnown := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server%s", parsed.Scheme, parsed.Host, path)
		meta, err := fetchJSON[AuthServerMeta](ctx, httpClient, wellKnown)
		if err == nil && meta.AuthorizationEndpoint != "" && meta.TokenEndpoint != "" {
			return meta, nil
		}
	}

	// Try RFC 8414 root: /.well-known/oauth-authorization-server
	wellKnown := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", parsed.Scheme, parsed.Host)
	meta, err := fetchJSON[AuthServerMeta](ctx, httpClient, wellKnown)
	if err == nil && meta.AuthorizationEndpoint != "" && meta.TokenEndpoint != "" {
		return meta, nil
	}

	// Fall back to OIDC Discovery: /.well-known/openid-configuration
	oidcURL := fmt.Sprintf("%s://%s/.well-known/openid-configuration", parsed.Scheme, parsed.Host)
	meta, err = fetchJSON[AuthServerMeta](ctx, httpClient, oidcURL)
	if err != nil {
		return nil, fmt.Errorf("%w: auth server metadata not found at %s", ErrDiscoveryFailed, authServerURL)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		return nil, fmt.Errorf("%w: incomplete auth server metadata at %s", ErrDiscoveryFailed, authServerURL)
	}

	return meta, nil
}

// ValidatePKCESupport checks that the authorization server supports S256 PKCE.
func ValidatePKCESupport(meta *AuthServerMeta) error {
	if len(meta.CodeChallengeMethodsSupported) == 0 {
		// If not declared, assume support (many servers don't advertise this).
		return nil
	}

	if !slices.Contains(meta.CodeChallengeMethodsSupported, "S256") {
		return ErrPKCENotSupported
	}

	return nil
}

// DiscoverUpstream orchestrates the full upstream discovery flow:
//  1. Fetch Protected Resource Metadata (RFC 9728)
//  2. Fetch Authorization Server Metadata (RFC 8414)
//  3. Validate PKCE support
func DiscoverUpstream(ctx context.Context, httpClient *http.Client, serverURL string) (*DiscoveryResult, error) {
	prMeta, err := DiscoverProtectedResource(ctx, httpClient, serverURL)
	if err != nil {
		return nil, err
	}

	if len(prMeta.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("%w: no authorization servers listed in protected resource metadata", ErrDiscoveryFailed)
	}

	asMeta, err := FetchAuthServerMetadata(ctx, httpClient, prMeta.AuthorizationServers[0])
	if err != nil {
		return nil, err
	}

	if err := ValidatePKCESupport(asMeta); err != nil {
		return nil, err
	}

	result := &DiscoveryResult{
		ResourceURI:          prMeta.Resource,
		AuthorizationURL:     asMeta.AuthorizationEndpoint,
		TokenURL:             asMeta.TokenEndpoint,
		RegistrationEndpoint: asMeta.RegistrationEndpoint,
	}

	if len(prMeta.ScopesSupported) > 0 {
		result.ScopesSupported = prMeta.ScopesSupported
	} else if len(asMeta.ScopesSupported) > 0 {
		result.ScopesSupported = asMeta.ScopesSupported
	}

	return result, nil
}

// fetchJSON performs a GET request and decodes the JSON response into T.
func fetchJSON[T any](ctx context.Context, httpClient *http.Client, rawURL string) (*T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, rawURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}

	return &result, nil
}
