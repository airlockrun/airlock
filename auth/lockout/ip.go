package lockout

import (
	"net"
	"net/netip"
)

// UnknownIP is the bucket assigned to requests whose RemoteAddr cannot be
// parsed. Aligns with the "fail loud" rule in airlock/CLAUDE.md: never
// silently skip the lockout — pool the unparseable requests instead.
const UnknownIP = "unknown"

// NormalizeIP turns an http.Request RemoteAddr into a stable bucket key.
// IPv4 round-trips to canonical form; IPv6 collapses to its /64 prefix
// because a single attacker controls their entire /64 trivially.
func NormalizeIP(remoteAddr string) string {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return UnknownIP
	}
	if addr.Is4() || addr.Is4In6() {
		return addr.Unmap().String()
	}
	bytes := addr.As16()
	for i := 8; i < 16; i++ {
		bytes[i] = 0
	}
	return netip.AddrFrom16(bytes).String()
}
