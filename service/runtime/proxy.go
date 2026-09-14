package runtime

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/networkpolicy"
)

func ConnectionUpstreamURL(policy *networkpolicy.Policy, baseURL, path string) (*url.URL, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("path must start with /")
	}
	base, err := policy.ParseURL(baseURL)
	if err != nil {
		return nil, err
	}
	upstream, err := policy.ParseURL(strings.TrimRight(baseURL, "/") + path)
	if err != nil {
		return nil, err
	}
	if !networkpolicy.SameOrigin(base, upstream) {
		return nil, errors.New("path changed the configured connection origin")
	}
	return upstream, nil
}

// applyHeaderMap merges m into h, using the empty-string-as-delete rule:
// a key whose value is "" removes any header of that name set by a lower
// layer. Non-empty values overwrite per-key.
func ApplyHeaderMap(h http.Header, m map[string]string) {
	for k, v := range m {
		if v == "" {
			h.Del(k)
			continue
		}
		h.Set(k, v)
	}
}

// decodeConnHeaders unmarshals the connection's headers jsonb column.
// A malformed value is treated as "no overrides" — the platform
// baseline and per-call layers still apply — and logged at the call
// site rather than here so we don't pull a logger into a pure helper.
func DecodeConnHeaders(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

// InjectAuth adds credentials to the upstream request based on the auth injection config.
func InjectAuth(req *http.Request, authInjectionJSON []byte, creds string) {
	var injection wire.AuthInjection
	if err := json.Unmarshal(authInjectionJSON, &injection); err != nil {
		return
	}

	switch injection.Type {
	case wire.AuthInjectBearer:
		req.Header.Set("Authorization", "Bearer "+creds)
	case wire.AuthInjectAPIKey:
		name := injection.Name
		if name == "" {
			name = "X-API-Key"
		}
		req.Header.Set(name, creds)
	case wire.AuthInjectPathPrefix:
		req.URL.Path = "/" + creds + req.URL.Path
	case wire.AuthInjectQueryParam:
		name := injection.Name
		if name == "" {
			name = "token"
		}
		q := req.URL.Query()
		q.Set(name, creds)
		req.URL.RawQuery = q.Encode()
	}
}
