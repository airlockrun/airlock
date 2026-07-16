package agentapi

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"testing"
)

func TestHTTPNetworkPolicyParseHTTPURL(t *testing.T) {
	publicOnly := newHTTPNetworkPolicy(nil)
	privateAllowed := newHTTPNetworkPolicy([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fd00::/8"),
	})
	cases := []struct {
		name      string
		policy    *httpNetworkPolicy
		raw       string
		wantError bool
	}{
		{"public https", publicOnly, "https://example.com/path", false},
		{"public http", publicOnly, "http://93.184.216.34/path", false},
		{"localhost hostname always blocked", privateAllowed, "http://localhost:8080/path", true},
		{"localhost subdomain always blocked", privateAllowed, "http://agent.localhost:8080/path", true},
		{"loopback always blocked", privateAllowed, "http://127.0.0.1/path", true},
		{"link-local always blocked", privateAllowed, "http://169.254.169.254/path", true},
		{"private blocked without allowlist", publicOnly, "http://10.0.0.1/path", true},
		{"private allowed", privateAllowed, "http://10.0.0.1/path", false},
		{"cgnat allowed", privateAllowed, "http://100.64.0.1/path", false},
		{"IPv6 ULA allowed", privateAllowed, "http://[fd00::1]/path", false},
		{"unsupported scheme", privateAllowed, "file:///etc/passwd", true},
		{"userinfo", privateAllowed, "https://user:pass@example.com/path", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.policy.parseHTTPURL(tt.raw)
			if (err != nil) != tt.wantError {
				t.Fatalf("parseHTTPURL() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestHTTPNetworkPolicyAllowsAddr(t *testing.T) {
	policy := newHTTPNetworkPolicy([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fd00::/8"),
	})
	cases := []struct {
		addr string
		want bool
	}{
		{"93.184.216.34", true},
		{"192.168.1.20", true},
		{"192.168.2.20", false},
		{"100.100.100.100", true},
		{"fd00::1", true},
		{"127.0.0.1", false},
		{"169.254.169.254", false},
		{"::1", false},
		{"fe80::1", false},
		{"0.0.0.0", false},
		{"224.0.0.1", false},
	}
	for _, tt := range cases {
		t.Run(tt.addr, func(t *testing.T) {
			if got := policy.allowsAddr(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Fatalf("allowsAddr(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestHTTPNetworkPolicyDialContextRejectsLocalhost(t *testing.T) {
	policy := newHTTPNetworkPolicy([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	})
	_, err := policy.dialContext(t.Context(), "tcp", "localhost:80")
	if !errors.Is(err, errDisallowedNetworkURL) {
		t.Fatalf("dialContext() error = %v, want %v", err, errDisallowedNetworkURL)
	}
}

func TestHTTPNetworkPolicyDialContextChecksResolvedAddresses(t *testing.T) {
	policy := newHTTPNetworkPolicy(nil)
	policy.resolver = lookupIPAddrFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.168.1.20")}}, nil
	})

	_, err := policy.dialContext(t.Context(), "tcp", "nas.internal:80")
	if !errors.Is(err, errDisallowedNetworkURL) {
		t.Fatalf("dialContext() error = %v, want %v", err, errDisallowedNetworkURL)
	}
}

func TestHTTPNetworkPolicyDisablesEnvironmentProxy(t *testing.T) {
	if proxy := newHTTPNetworkPolicy(nil).transport.Proxy; proxy != nil {
		t.Fatal("transport.Proxy is set, want environment proxies disabled")
	}
}

type lookupIPAddrFunc func(context.Context, string) ([]net.IPAddr, error)

func (f lookupIPAddrFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

func TestSameHTTPOrigin(t *testing.T) {
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	tests := []struct {
		a, b string
		want bool
	}{
		{"https://example.com/start", "https://example.com/next", true},
		{"https://example.com/start", "https://example.com:443/next", true},
		{"https://example.com/start", "http://example.com/next", false},
		{"https://example.com/start", "https://other.example/next", false},
		{"https://example.com/start", "https://example.com:8443/next", false},
	}
	for _, tt := range tests {
		if got := sameHTTPOrigin(parse(tt.a), parse(tt.b)); got != tt.want {
			t.Errorf("sameHTTPOrigin(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIsPublicAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"93.184.216.34", true},
		{"192.0.0.9", true},
		{"64:ff9b::5db8:d822", true},
		{"2001:20::1", true},
		{"2606:2800:220:1:248:1893:25c8:1946", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"169.254.1.1", false},
		{"198.18.0.1", false},
		{"192.0.2.1", false},
		{"::1", false},
		{"fc00::1", false},
		{"2001:db8::1", false},
		{"100:0:0:1::1", false},
	}
	for _, tt := range cases {
		t.Run(tt.addr, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			if got := isPublicAddr(addr); got != tt.want {
				t.Fatalf("isPublicAddr(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}
