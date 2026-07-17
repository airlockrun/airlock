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
	"net/netip"
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
	if !validSecureURL(parsed) {
		return nil, errors.New("server URL must be an absolute HTTPS URL")
	}

	// Try path-aware well-known first: /.well-known/oauth-protected-resource/{path}
	path := strings.TrimRight(parsed.Path, "/")
	if path != "" && path != "/" {
		wellKnown := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource%s", parsed.Scheme, parsed.Host, path)
		meta, err := fetchJSON[ProtectedResourceMeta](ctx, httpClient, wellKnown)
		if err == nil {
			if err := validateProtectedResourceMeta(meta, parsed); err != nil {
				return nil, err
			}
			return meta, nil
		}
	}

	// Fall back to root: /.well-known/oauth-protected-resource
	wellKnown := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", parsed.Scheme, parsed.Host)
	meta, err := fetchJSON[ProtectedResourceMeta](ctx, httpClient, wellKnown)
	if err != nil {
		return nil, fmt.Errorf("%w: protected resource metadata not found at %s: %v", ErrDiscoveryFailed, serverURL, err)
	}
	if err := validateProtectedResourceMeta(meta, parsed); err != nil {
		return nil, err
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
	if !validSecureURL(parsed) {
		return nil, errors.New("authorization server URL must be an absolute HTTPS URL")
	}

	// Try RFC 8414 path-aware: /.well-known/oauth-authorization-server/{path}
	path := strings.TrimRight(parsed.Path, "/")
	if path != "" && path != "/" {
		wellKnown := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server%s", parsed.Scheme, parsed.Host, path)
		meta, err := fetchJSON[AuthServerMeta](ctx, httpClient, wellKnown)
		if err == nil && validateAuthServerMeta(meta, parsed) == nil {
			return meta, nil
		}
	}

	// Try RFC 8414 root: /.well-known/oauth-authorization-server
	wellKnown := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", parsed.Scheme, parsed.Host)
	meta, err := fetchJSON[AuthServerMeta](ctx, httpClient, wellKnown)
	if err == nil && validateAuthServerMeta(meta, parsed) == nil {
		return meta, nil
	}

	// Fall back to OIDC Discovery: /.well-known/openid-configuration
	oidcURL := fmt.Sprintf("%s://%s/.well-known/openid-configuration", parsed.Scheme, parsed.Host)
	meta, err = fetchJSON[AuthServerMeta](ctx, httpClient, oidcURL)
	if err != nil {
		return nil, fmt.Errorf("%w: auth server metadata not found at %s", ErrDiscoveryFailed, authServerURL)
	}
	if err := validateAuthServerMeta(meta, parsed); err != nil {
		return nil, fmt.Errorf("%w: invalid auth server metadata at %s: %v", ErrDiscoveryFailed, authServerURL, err)
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
	if httpClient == nil {
		panic("oauth: HTTP client is required")
	}
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) > maxOAuthResponseBytes {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", rawURL, maxOAuthResponseBytes)
	}

	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}

	return &result, nil
}

func validateProtectedResourceMeta(meta *ProtectedResourceMeta, requested *url.URL) error {
	resource, err := url.Parse(meta.Resource)
	if err != nil || !validSecureURL(resource) || !sameOrigin(resource, requested) {
		return fmt.Errorf("%w: protected resource metadata has invalid resource", ErrDiscoveryFailed)
	}
	if len(meta.AuthorizationServers) == 0 {
		return fmt.Errorf("%w: no authorization servers listed in protected resource metadata", ErrDiscoveryFailed)
	}
	for _, raw := range meta.AuthorizationServers {
		u, err := url.Parse(raw)
		if err != nil || !validSecureURL(u) {
			return fmt.Errorf("%w: invalid authorization server URL", ErrDiscoveryFailed)
		}
	}
	return nil
}

func validateAuthServerMeta(meta *AuthServerMeta, requested *url.URL) error {
	issuer, err := url.Parse(meta.Issuer)
	if err != nil || !validSecureURL(issuer) || normalizeURL(issuer) != normalizeURL(requested) {
		return errors.New("issuer does not match the requested authorization server")
	}
	for name, raw := range map[string]string{
		"authorization_endpoint": meta.AuthorizationEndpoint,
		"token_endpoint":         meta.TokenEndpoint,
	} {
		u, err := url.Parse(raw)
		if err != nil || !validSecureURL(u) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if meta.RegistrationEndpoint != "" {
		u, err := url.Parse(meta.RegistrationEndpoint)
		if err != nil || !validSecureURL(u) {
			return errors.New("registration_endpoint is invalid")
		}
	}
	return nil
}

func validSecureURL(u *url.URL) bool {
	if u == nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLocalhost(u.Hostname()))
}

func isLocalhost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

func port(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func normalizeURL(u *url.URL) string {
	copy := *u
	copy.RawQuery = ""
	copy.Fragment = ""
	copy.Path = strings.TrimRight(copy.Path, "/")
	return copy.String()
}
