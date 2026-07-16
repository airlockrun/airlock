package agentapi

import (
	"net/netip"
	"net/url"
	"testing"
)

func TestParsePublicHTTPURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"public https", "https://example.com/path", false},
		{"public http", "http://93.184.216.34/path", false},
		{"localhost", "http://localhost:8080/path", false},
		{"loopback ip", "http://127.0.0.1/path", true},
		{"private ip", "http://10.0.0.1/path", true},
		{"cgnat ip", "http://100.64.0.1/path", true},
		{"unsupported scheme", "file:///etc/passwd", true},
		{"userinfo", "https://user:pass@example.com/path", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePublicHTTPURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePublicHTTPURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
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
		{"2606:2800:220:1:248:1893:25c8:1946", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"169.254.1.1", false},
		{"::1", false},
		{"fc00::1", false},
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
