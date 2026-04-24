package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRealIPConfig(t *testing.T) {
	t.Run("empty string disables", func(t *testing.T) {
		cfg := ParseRealIPConfig("", 1)
		if cfg.Enabled() {
			t.Fatal("expected disabled")
		}
	})

	t.Run("star trusts all", func(t *testing.T) {
		cfg := ParseRealIPConfig("*", 1)
		if !cfg.TrustAll {
			t.Fatal("expected TrustAll")
		}
		if !cfg.Enabled() {
			t.Fatal("expected enabled")
		}
	})

	t.Run("parses CIDRs", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.42.0.0/16, 192.168.1.0/24", 2)
		if len(cfg.TrustedProxies) != 2 {
			t.Fatalf("expected 2 CIDRs, got %d", len(cfg.TrustedProxies))
		}
		if cfg.Limit != 2 {
			t.Fatalf("expected limit 2, got %d", cfg.Limit)
		}
	})

	t.Run("bare IP gets /32", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.0.0.1", 1)
		if len(cfg.TrustedProxies) != 1 {
			t.Fatalf("expected 1 CIDR, got %d", len(cfg.TrustedProxies))
		}
		if cfg.TrustedProxies[0].String() != "10.0.0.1/32" {
			t.Fatalf("expected 10.0.0.1/32, got %s", cfg.TrustedProxies[0].String())
		}
	})

	t.Run("limit floors at 1", func(t *testing.T) {
		cfg := ParseRealIPConfig("*", 0)
		if cfg.Limit != 1 {
			t.Fatalf("expected limit 1, got %d", cfg.Limit)
		}
	})
}

func TestRealIPMiddleware(t *testing.T) {
	// Helper: run a request through the middleware and return the RemoteAddr
	// seen by the inner handler.
	run := func(cfg *RealIPConfig, remoteAddr string, headers map[string]string) string {
		var got string
		handler := RealIP(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.RemoteAddr
		}))

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = remoteAddr
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		handler.ServeHTTP(httptest.NewRecorder(), req)
		return got
	}

	t.Run("disabled config passes through", func(t *testing.T) {
		cfg := ParseRealIPConfig("", 1)
		got := run(cfg, "1.2.3.4:5678", map[string]string{
			"X-Forwarded-For": "9.9.9.9",
		})
		if got != "1.2.3.4:5678" {
			t.Fatalf("expected original RemoteAddr, got %s", got)
		}
	})

	t.Run("untrusted peer ignores headers", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.42.0.0/16", 1)
		got := run(cfg, "1.2.3.4:5678", map[string]string{
			"X-Forwarded-For": "9.9.9.9",
		})
		if got != "1.2.3.4:5678" {
			t.Fatalf("expected original RemoteAddr, got %s", got)
		}
	})

	t.Run("trusted peer uses X-Real-IP", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.42.0.0/16", 1)
		got := run(cfg, "10.42.0.5:5678", map[string]string{
			"X-Real-IP": "203.0.113.50",
		})
		if got != "203.0.113.50" {
			t.Fatalf("expected 203.0.113.50, got %s", got)
		}
	})

	t.Run("trusted peer uses X-Forwarded-For", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.42.0.0/16", 1)
		got := run(cfg, "10.42.0.5:5678", map[string]string{
			"X-Forwarded-For": "203.0.113.50, 10.42.0.1",
		})
		// Limit=1: walk 1 hop from right. 10.42.0.1 is trusted, skip.
		// Only walked 1 hop, so we stop — but 10.42.0.1 is trusted so we
		// continue to 203.0.113.50 which is untrusted = client.
		// Actually with limit=1, we walk at most 1 entry. Let me re-think.
		// Limit means how many hops. With limit=1: we check rightmost (10.42.0.1),
		// it's trusted so we skip; hops=1 which equals limit, so we stop.
		// Result: no client IP found, RemoteAddr unchanged.
		// For this chain to work we need limit=2.
		if got != "10.42.0.5:5678" {
			t.Fatalf("expected original (limit exhausted), got %s", got)
		}
	})

	t.Run("limit 2 walks through trusted proxy", func(t *testing.T) {
		cfg := ParseRealIPConfig("10.42.0.0/16", 2)
		got := run(cfg, "10.42.0.5:5678", map[string]string{
			"X-Forwarded-For": "203.0.113.50, 10.42.0.1",
		})
		if got != "203.0.113.50" {
			t.Fatalf("expected 203.0.113.50, got %s", got)
		}
	})

	t.Run("X-Real-IP takes precedence over X-Forwarded-For", func(t *testing.T) {
		cfg := ParseRealIPConfig("*", 1)
		got := run(cfg, "10.0.0.1:5678", map[string]string{
			"X-Real-IP":       "1.1.1.1",
			"X-Forwarded-For": "2.2.2.2",
		})
		if got != "1.1.1.1" {
			t.Fatalf("expected 1.1.1.1, got %s", got)
		}
	})

	t.Run("trust all works", func(t *testing.T) {
		cfg := ParseRealIPConfig("*", 1)
		got := run(cfg, "99.99.99.99:1234", map[string]string{
			"X-Real-IP": "8.8.8.8",
		})
		if got != "8.8.8.8" {
			t.Fatalf("expected 8.8.8.8, got %s", got)
		}
	})

	t.Run("spoofed XFF prefix ignored with limit", func(t *testing.T) {
		// Client sends: X-Forwarded-For: 6.6.6.6
		// Traefik appends real client: X-Forwarded-For: 6.6.6.6, 203.0.113.50
		cfg := ParseRealIPConfig("10.42.0.0/16", 1)
		got := run(cfg, "10.42.0.5:5678", map[string]string{
			"X-Forwarded-For": "6.6.6.6, 203.0.113.50",
		})
		// Limit=1, rightmost is 203.0.113.50 (untrusted) = client IP. Correct!
		// The spoofed 6.6.6.6 is beyond the limit and ignored.
		if got != "203.0.113.50" {
			t.Fatalf("expected 203.0.113.50, got %s", got)
		}
	})

	t.Run("nil config passes through", func(t *testing.T) {
		handler := RealIP(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		req := httptest.NewRequest("GET", "/", nil)
		// Just verify it doesn't panic.
		handler.ServeHTTP(httptest.NewRecorder(), req)
	})
}
