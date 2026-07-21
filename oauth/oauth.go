// Package oauth provides OAuth 2.0 PKCE support for Airlock credential management.
// Ported from gateway/internal/tokenbroker — simplified to flat params, no discovery.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TokenResponse represents the response from an OAuth token endpoint.
type TokenResponse struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64 // seconds
	Scope        string
	ScopePresent bool
}

// Client handles OAuth 2.0 operations.
type Client struct {
	httpClient             *http.Client
	allowInsecureLocalhost bool
}

// NewClient creates a new OAuth client.
func NewClient(httpClient *http.Client, allowInsecureLocalhost bool) *Client {
	if httpClient == nil {
		panic("oauth: HTTP client is required")
	}
	return &Client{httpClient: httpClient, allowInsecureLocalhost: allowInsecureLocalhost}
}

var reservedAuthParams = map[string]struct{}{
	"client_id": {}, "redirect_uri": {}, "state": {}, "response_type": {},
	"code_challenge": {}, "code_challenge_method": {}, "scope": {},
}

// ValidateAuthParams rejects parameters that could replace OAuth's identity,
// callback, CSRF, response type, or PKCE binding.
func ValidateAuthParams(params map[string]string) error {
	for key := range params {
		if _, reserved := reservedAuthParams[strings.ToLower(strings.TrimSpace(key))]; reserved {
			return fmt.Errorf("OAuth authorization parameter %q is reserved", key)
		}
	}
	return nil
}

// GeneratePKCE generates a PKCE code verifier and S256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// GenerateState generates a random state token for CSRF protection.
func GenerateState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// BuildAuthURL constructs an OAuth 2.0 authorization URL with PKCE.
// extraParams are provider-specific query parameters merged in last —
// e.g. access_type=offline to request a refresh token.
func (c *Client) BuildAuthURL(authURL, clientID, redirectURI, state, codeChallenge, scopes string, extraParams map[string]string) (string, error) {
	if err := ValidateAuthParams(extraParams); err != nil {
		return "", err
	}
	u, err := url.Parse(authURL)
	if err != nil {
		return "", fmt.Errorf("parse authorization url: %w", err)
	}
	if !validHTTPSURL(u) && !(c.allowInsecureLocalhost && validSecureURL(u)) {
		return "", errors.New("authorization URL must be an absolute HTTPS URL")
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	if scopes = CanonicalScopes(scopes); scopes != "" {
		q.Set("scope", scopes)
	}
	for k, v := range extraParams {
		q.Set(k, v)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func validHTTPSURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

// ExchangeCode exchanges an authorization code for tokens.
func (c *Client) ExchangeCode(ctx context.Context, tokenURL, code, codeVerifier, redirectURI, clientID, clientSecret string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("code_verifier", codeVerifier)

	return c.tokenRequest(ctx, tokenURL, data, clientID, clientSecret)
}

// RefreshToken uses a refresh token to obtain a new access token.
func (c *Client) RefreshToken(ctx context.Context, tokenURL, refreshToken, clientID, clientSecret string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)

	return c.tokenRequest(ctx, tokenURL, data, clientID, clientSecret)
}

// tokenRequest makes a POST request to a token endpoint and parses the response.
func (c *Client) tokenRequest(ctx context.Context, tokenURL string, data url.Values, clientID, clientSecret string) (*TokenResponse, error) {
	if clientSecret != "" {
		data.Del("client_id")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if len(body) > maxOAuthResponseBytes {
		return nil, fmt.Errorf("token response exceeds %d bytes", maxOAuthResponseBytes)
	}

	// RFC 6749 §5.2 errors arrive as 400 + JSON `{"error":"…"}`. Try to
	// extract the typed OAuthError *before* the status-code fallback so
	// callers can branch on Code == "invalid_grant" (refresh-job uses
	// this to clear revoked credentials so the UI reflects the disconnected
	// state instead of showing a stale "authorized" badge). Only fall
	// through to the opaque "status %d" error if the body doesn't carry a
	// recognisable OAuth error code.
	var tokenResp struct {
		AccessToken  string  `json:"access_token"`
		RefreshToken string  `json:"refresh_token"`
		TokenType    string  `json:"token_type"`
		ExpiresIn    int64   `json:"expires_in"`
		Scope        *string `json:"scope"`
		Error        string  `json:"error"`
		ErrorDesc    string  `json:"error_description"`
	}
	jsonErr := json.Unmarshal(body, &tokenResp)
	if jsonErr == nil && tokenResp.Error != "" {
		return nil, &OAuthError{
			Code:        limitedErrorBody([]byte(tokenResp.Error)),
			Description: limitedErrorBody([]byte(tokenResp.ErrorDesc)),
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, limitedErrorBody(body))
	}

	if jsonErr != nil {
		return nil, fmt.Errorf("parse token response: %w", jsonErr)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response")
	}

	result := &TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
	}
	if tokenResp.Scope != nil {
		result.Scope = CanonicalScopes(*tokenResp.Scope)
		result.ScopePresent = true
	}
	return result, nil
}

const maxOAuthResponseBytes = 1 << 20

func limitedErrorBody(body []byte) string {
	const limit = 4096
	if len(body) > limit {
		body = body[:limit]
	}
	return string(body)
}

// OAuthError represents an error returned by the OAuth provider.
type OAuthError struct {
	Code        string // e.g. "invalid_grant"
	Description string
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth error: %s - %s", e.Code, e.Description)
	}
	return fmt.Sprintf("oauth error: %s", e.Code)
}
