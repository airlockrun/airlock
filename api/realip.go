package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

const proxyAuthHeader = "X-Airlock-Proxy-Auth"

// RealIPConfig configures the real IP extraction middleware.
type RealIPConfig struct {
	// TrustedPeers limits which immediate network peers may present authenticated
	// forwarding headers. The shared secret remains required for every match.
	TrustedPeers []*net.IPNet

	proxyAuthHash [sha256.Size]byte

	// Limit selects the exact rightmost entry in X-Forwarded-For.
	// Default: 1 (single proxy).
	Limit int
}

// ParseRealIPConfig builds a RealIPConfig from the raw env values.
// trustedPeers is a comma-separated list of immediate-peer CIDRs.
// limit is the number of proxy hops (minimum 1).
func ParseRealIPConfig(trustedPeers string, limit int, proxyAuthSecret string) *RealIPConfig {
	if proxyAuthSecret == "" {
		panic("REVERSE_PROXY_AUTH_SECRET is required")
	}
	if limit < 1 {
		panic("REVERSE_PROXY_LIMIT must be at least 1")
	}

	cfg := &RealIPConfig{
		Limit:         limit,
		proxyAuthHash: sha256.Sum256([]byte(proxyAuthSecret)),
	}

	raw := strings.TrimSpace(trustedPeers)
	if raw == "" {
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
			panic("REVERSE_PROXY_TRUSTED_PEERS: invalid CIDR " + entry + ": " + err.Error())
		}
		cfg.TrustedPeers = append(cfg.TrustedPeers, cidr)
	}
	return cfg
}

// Enabled returns true if any proxy trust is configured.
func (c *RealIPConfig) Enabled() bool {
	return len(c.TrustedPeers) > 0
}

// isTrustedPeer checks whether ip falls within an eligible direct-peer CIDR.
func (c *RealIPConfig) isTrustedPeer(ip net.IP) bool {
	for _, cidr := range c.TrustedPeers {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *RealIPConfig) authenticates(value string) bool {
	got := sha256.Sum256([]byte(value))
	return subtle.ConstantTimeCompare(got[:], c.proxyAuthHash[:]) == 1
}

// RealIP returns middleware that canonicalizes r.RemoteAddr to an IP and,
// when the direct peer is trusted, replaces it with the forwarded client IP.
// Forwarding headers are removed before downstream handlers run so
// r.RemoteAddr remains the only client-IP source inside the application.
func RealIP(cfg *RealIPConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		panic("api.RealIP: nil config")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peerIP := parseRemoteAddr(r.RemoteAddr)
			proxyAuth := r.Header.Get(proxyAuthHeader)
			r.Header.Del(proxyAuthHeader)
			if peerIP != nil {
				r.RemoteAddr = peerIP.String()
			}

			if peerIP != nil && cfg.isTrustedPeer(peerIP) && cfg.authenticates(proxyAuth) {
				// X-Forwarded-For is preferred because conforming proxies append
				// to it. X-Real-IP is accepted only as a single-hop fallback.
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					if clientIP := extractFromXFF(xff, cfg); clientIP != "" {
						r.RemoteAddr = clientIP
					}
				} else if rip := r.Header.Get("X-Real-IP"); rip != "" {
					if ip := net.ParseIP(strings.TrimSpace(rip)); ip != nil {
						r.RemoteAddr = ip.String()
					}
				}
			}

			r.Header.Del("Forwarded")
			r.Header.Del("X-Forwarded-For")
			r.Header.Del("X-Real-IP")
			next.ServeHTTP(w, r)
		})
	}
}

// extractFromXFF returns the configured rightmost hop. Caddy sanitizes an
// untrusted incoming chain before appending its peer, so a fixed hop count
// cannot be moved by a client-controlled prefix.
func extractFromXFF(xff string, cfg *RealIPConfig) string {
	parts := strings.Split(xff, ",")
	ips := make([]net.IP, len(parts))
	for i, part := range parts {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip == nil {
			return ""
		}
		ips[i] = ip
	}
	if len(ips) < cfg.Limit {
		return ""
	}
	return ips[len(ips)-cfg.Limit].String()
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
