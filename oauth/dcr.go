package oauth

// Dynamic Client Registration (RFC 7591). Used by oauth_discovery MCP
// servers to register an airlock-issued client_id (and client_secret for
// confidential clients) without operator paste. Trade-off vs the manual
// `oauth` mode: the server has to advertise a registration_endpoint via
// RFC 8414 metadata; if it doesn't, the operator switches the MCP
// server's auth_mode to `oauth` and pastes credentials by hand.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ErrDCRUnsupported is returned when the registration endpoint is empty
// (the server didn't advertise one in its discovery metadata). The
// operator's only path forward is to switch auth_mode to `oauth` and
// paste credentials manually.
var ErrDCRUnsupported = errors.New("server does not advertise an RFC 7591 registration endpoint")

// RegisterClientRequest is the body posted to the registration endpoint
// per RFC 7591 §2. We send the minimal set: a name (informational),
// a single redirect URI, the grant types we'll actually use, and the
// requested scopes when known. Anything else is server-default.
type RegisterClientRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// RegisterClientResponse covers the RFC 7591 §3.2.1 response fields we
// actually consume. Any others (client_id_issued_at, expires_at,
// registration_access_token, …) are deliberately ignored — we don't
// support runtime registration management in v1, so we treat the
// returned client_id as opaque-and-permanent until the operator hits
// "Reconfigure" to register a new one.
type RegisterClientResponse struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"` // empty for public clients
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
}

// RegisterClient performs RFC 7591 dynamic client registration against
// the given registration endpoint. Returns the issued client_id (and
// client_secret if the server treats us as a confidential client).
//
// Errors:
//   - ErrDCRUnsupported when registrationEndpoint is empty.
//   - Wrapped HTTP error (status + body) when the server returns >= 400
//     so the operator sees the server's actual rejection reason.
func RegisterClient(ctx context.Context, httpClient *http.Client, registrationEndpoint, clientName, redirectURI, scope string) (*RegisterClientResponse, error) {
	if registrationEndpoint == "" {
		return nil, ErrDCRUnsupported
	}
	if redirectURI == "" {
		return nil, errors.New("redirectURI is required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	body := RegisterClientRequest{
		ClientName:              clientName,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   scope,
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", registrationEndpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration POST %s: %w", registrationEndpoint, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("registration endpoint %s returned status %d: %s", registrationEndpoint, resp.StatusCode, string(respBody))
	}

	var out RegisterClientResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode registration response: %w", err)
	}
	if out.ClientID == "" {
		return nil, fmt.Errorf("registration response missing client_id (body: %s)", string(respBody))
	}
	return &out, nil
}
