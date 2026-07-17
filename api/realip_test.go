package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const realIPTestSecret = "real-ip-test-proxy-secret-at-least-32-bytes"

func TestParseRealIPConfig(t *testing.T) {
	t.Run("empty peers disables", func(t *testing.T) {
		cfg := ParseRealIPConfig("", 1, realIPTestSecret)
		if cfg.Enabled() {
			t.Fatal("expected disabled")
		}
	})

	t.Run("parses CIDRs", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.42.0.0/16, 192.168.1.0/24", 2, realIPTestSecret)
		if len(cfg.TrustedPeers) != 2 {
			t.Fatalf("expected 2 CIDRs, got %d", len(cfg.TrustedPeers))
		}
		if cfg.Limit != 2 {
			t.Fatalf("expected limit 2, got %d", cfg.Limit)
		}
	})

	t.Run("bare IP gets /32", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.0.0.1", 1, realIPTestSecret)
		if len(cfg.TrustedPeers) != 1 {
			t.Fatalf("expected 1 CIDR, got %d", len(cfg.TrustedPeers))
		}
		if cfg.TrustedPeers[0].String() != "10.0.0.1/32" {
			t.Fatalf("expected 10.0.0.1/32, got %s", cfg.TrustedPeers[0].String())
		}
	})

	t.Run("invalid limit panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		ParseRealIPConfig("10.0.0.0/8", 0, realIPTestSecret)
	})

	t.Run("secret is required", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		ParseRealIPConfig("10.0.0.0/8", 1, "")
	})
}

func TestRealIPMiddleware(t *testing.T) {
	run := func(cfg *RealIPConfig, remoteAddr string, headers map[string]string) string {
		t.Helper()
		var got string
		handler := RealIP(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.RemoteAddr
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		handler.ServeHTTP(httptest.NewRecorder(), req)
		return got
	}

	authenticated := func(forwardedFor string) map[string]string {
		return map[string]string{
			proxyAuthHeader:   realIPTestSecret,
			"X-Forwarded-For": forwardedFor,
		}
	}

	t.Run("disabled config canonicalizes direct peer", func(t *testing.T) {
		got := run(ParseRealIPConfig("", 1, realIPTestSecret), "1.2.3.4:5678", authenticated("9.9.9.9"))
		if got != "1.2.3.4" {
			t.Fatalf("expected canonical direct peer, got %s", got)
		}
	})

	t.Run("untrusted peer ignores authenticated headers", func(t *testing.T) {
		got := run(ParseRealIPConfig("10.42.0.0/16", 1, realIPTestSecret), "1.2.3.4:5678", authenticated("9.9.9.9"))
		if got != "1.2.3.4" {
			t.Fatalf("expected canonical direct peer, got %s", got)
		}
	})

	for _, tc := range []struct {
		name   string
		secret string
	}{
		{"missing proxy auth", ""},
		{"incorrect proxy auth", "attacker-controlled-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := authenticated("203.0.113.50")
			headers[proxyAuthHeader] = tc.secret
			got := run(ParseRealIPConfig("10.42.0.0/16", 1, realIPTestSecret), "10.42.0.5:5678", headers)
			if got != "10.42.0.5" {
				t.Fatalf("spoofed forwarding header changed address to %s", got)
			}
		})
	}

	t.Run("authenticated peer uses X-Real-IP", func(t *testing.T) {
		headers := map[string]string{proxyAuthHeader: realIPTestSecret, "X-Real-IP": "203.0.113.50"}
		got := run(ParseRealIPConfig("10.42.0.0/16", 1, realIPTestSecret), "10.42.0.5:5678", headers)
		if got != "203.0.113.50" {
			t.Fatalf("expected 203.0.113.50, got %s", got)
		}
	})

	t.Run("single proxy uses rightmost XFF", func(t *testing.T) {
		got := run(ParseRealIPConfig("10.42.0.0/16", 1, realIPTestSecret), "10.42.0.5:5678", authenticated("6.6.6.6, 203.0.113.50"))
		if got != "203.0.113.50" {
			t.Fatalf("expected 203.0.113.50, got %s", got)
		}
	})

	t.Run("external proxy chain uses second rightmost XFF", func(t *testing.T) {
		got := run(ParseRealIPConfig("10.42.0.0/16", 2, realIPTestSecret), "10.42.0.5:5678", authenticated("6.6.6.6, 203.0.113.50, 10.42.0.1"))
		if got != "203.0.113.50" {
			t.Fatalf("expected 203.0.113.50, got %s", got)
		}
	})

	t.Run("private clients remain distinct", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.0.0.0/8,172.16.0.0/12", 1, realIPTestSecret)
		for _, client := range []string{"10.20.30.40", "172.20.30.40"} {
			if got := run(cfg, "172.18.0.5:5678", authenticated(client)); got != client {
				t.Fatalf("client %s became %s", client, got)
			}
		}
	})

	t.Run("malformed XFF fails closed", func(t *testing.T) {
		got := run(ParseRealIPConfig("10.42.0.0/16", 1, realIPTestSecret), "10.42.0.5:5678", authenticated("spoofed, 203.0.113.50"))
		if got != "10.42.0.5" {
			t.Fatalf("malformed chain changed address to %s", got)
		}
	})

	t.Run("forwarding and auth headers do not reach handlers", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.42.0.0/16", 1, realIPTestSecret)
		var got http.Header
		handler := RealIP(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Clone()
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.42.0.5:5678"
		req.Header.Set("Forwarded", "for=203.0.113.50")
		req.Header.Set("X-Forwarded-For", "203.0.113.50")
		req.Header.Set("X-Real-IP", "203.0.113.50")
		req.Header.Set(proxyAuthHeader, realIPTestSecret)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", proxyAuthHeader} {
			if got.Get(name) != "" {
				t.Errorf("%s reached downstream handler", name)
			}
		}
	})

	t.Run("nil config panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		RealIP(nil)
	})
}
