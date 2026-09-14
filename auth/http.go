package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type proxySchemeKey struct{}

// WithAuthenticatedProxyScheme is called only after the immediate proxy peer
// and its configured shared credential have both been authenticated.
func WithAuthenticatedProxyScheme(ctx context.Context, scheme string) context.Context {
	if scheme != "http" && scheme != "https" {
		panic("auth: invalid authenticated proxy scheme")
	}
	return context.WithValue(ctx, proxySchemeKey{}, scheme)
}

func RequestScheme(r *http.Request) string {
	if scheme, ok := r.Context().Value(proxySchemeKey{}).(string); ok {
		return scheme
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// RequestBearerToken rejects ambiguous credentials, including duplicate header lines.
// An absent header is distinct from a supplied empty or malformed header.
func RequestBearerToken(r *http.Request) (token string, supplied bool, err error) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", true, errors.New("duplicate authorization header")
	}
	token, err = BearerToken(values[0])
	return token, true, err
}

// UniqueCookie rejects cookie shadowing across paths and domains.
func UniqueCookie(r *http.Request, name string) (*http.Cookie, error) {
	occurrences := 0
	for _, header := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(header, ";") {
			key, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if key == name {
				occurrences++
			}
		}
	}
	if occurrences > 1 {
		return nil, errors.New("duplicate authentication cookie")
	}
	var found *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != name {
			continue
		}
		if found != nil {
			return nil, errors.New("duplicate authentication cookie")
		}
		found = cookie
	}
	if found == nil {
		if occurrences != 0 {
			return nil, errors.New("malformed authentication cookie")
		}
		return nil, http.ErrNoCookie
	}
	if found.Value == "" {
		return nil, errors.New("empty authentication cookie")
	}
	return found, nil
}
