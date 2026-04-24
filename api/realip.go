package api

import (
	"net"
	"net/http"
	"strings"
)

// RealIPConfig configures the real IP extraction middleware.
type RealIPConfig struct {
	// TrustedProxies is a list of CIDR ranges whose X-Forwarded-For / X-Real-IP
	// headers are trusted. If empty, no headers are trusted and r.RemoteAddr is
	// used as-is. A single entry of "*" trusts all sources.
	TrustedProxies []*net.IPNet

	// TrustAll is set when the configured value is "*".
	TrustAll bool

	// Limit is how many rightmost entries in X-Forwarded-For to walk.
	// Default: 1 (single proxy).
	Limit int
}

// ParseRealIPConfig builds a RealIPConfig from the raw env values.
// trustedProxies is a comma-separated list of CIDRs or "*".
// limit is the number of proxy hops (minimum 1).
func ParseRealIPConfig(trustedProxies string, limit int) *RealIPConfig {
	if limit < 1 {
		limit = 1
	}

	cfg := &RealIPConfig{Limit: limit}

	raw := strings.TrimSpace(trustedProxies)
	if raw == "" {
		return cfg
	}
	if raw == "*" {
		cfg.TrustAll = true
		return cfg
	}

	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// If it's a bare IP (no mask), add /32 or /128.
		if !strings.Contains(entry, "/") {
			if strings.Contains(entry, ":") {
				entry += "/128"
			} else {
				entry += "/32"
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			panic("REVERSE_PROXY_TRUSTED_PROXIES: invalid CIDR " + entry + ": " + err.Error())
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, cidr)
	}
	return cfg
}

// Enabled returns true if any proxy trust is configured.
func (c *RealIPConfig) Enabled() bool {
	return c.TrustAll || len(c.TrustedProxies) > 0
}

// isTrusted checks whether ip falls within any trusted CIDR.
func (c *RealIPConfig) isTrusted(ip net.IP) bool {
	if c.TrustAll {
		return true
	}
	for _, cidr := range c.TrustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// RealIP returns middleware that overwrites r.RemoteAddr with the client's
// real IP extracted from X-Real-IP or X-Forwarded-For, but only when the
// direct connection comes from a trusted proxy.
func RealIP(cfg *RealIPConfig) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled() {
		// No trusted proxies configured — pass through unchanged.
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Parse the direct peer IP from r.RemoteAddr (ip:port).
			peerIP := parseRemoteAddr(r.RemoteAddr)
			if peerIP == nil || !cfg.isTrusted(peerIP) {
				// Direct connection is not from a trusted proxy — don't
				// trust any forwarded headers.
				next.ServeHTTP(w, r)
				return
			}

			// Try X-Real-IP first (single value, set by first proxy).
			if rip := r.Header.Get("X-Real-IP"); rip != "" {
				if ip := net.ParseIP(strings.TrimSpace(rip)); ip != nil {
					r.RemoteAddr = ip.String()
					next.ServeHTTP(w, r)
					return
				}
			}

			// Walk X-Forwarded-For right-to-left, skipping trusted proxies,
			// up to cfg.Limit hops.
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				if clientIP := extractFromXFF(xff, cfg); clientIP != "" {
					r.RemoteAddr = clientIP
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractFromXFF walks the X-Forwarded-For chain right-to-left.
// It skips trusted proxy IPs and returns the first untrusted IP,
// stopping after cfg.Limit hops.
func extractFromXFF(xff string, cfg *RealIPConfig) string {
	parts := strings.Split(xff, ",")

	// Walk right-to-left.
	hops := 0
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if candidate == "" {
			continue
		}
		ip := net.ParseIP(candidate)
		if ip == nil {
			continue
		}
		hops++
		if hops > cfg.Limit {
			break
		}
		if !cfg.isTrusted(ip) {
			return ip.String()
		}
	}

	// All entries were trusted proxies (or empty) — no client IP found.
	return ""
}

// parseRemoteAddr extracts the IP from a host:port string.
func parseRemoteAddr(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Maybe it's just an IP without port.
		return net.ParseIP(addr)
	}
	return net.ParseIP(host)
}
