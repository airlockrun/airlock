package networkpolicy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestPolicyParseURL(t *testing.T) {
	publicOnly := New(nil, false)
	privateAllowed := New([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fd00::/8"),
	}, false)
	tests := []struct {
		name    string
		policy  *Policy
		raw     string
		wantErr bool
	}{
		{"public HTTPS", publicOnly, "https://example.com/path", false},
		{"public HTTP", publicOnly, "http://93.184.216.34/path", true},
		{"localhost blocked", privateAllowed, "https://localhost/path", true},
		{"loopback blocked", privateAllowed, "https://127.0.0.1/path", true},
		{"link-local blocked", privateAllowed, "https://169.254.169.254/path", true},
		{"private blocked", publicOnly, "https://10.0.0.1/path", true},
		{"private explicitly allowed", privateAllowed, "https://10.0.0.1/path", false},
		{"unsupported scheme", privateAllowed, "file:///etc/passwd", true},
		{"userinfo", privateAllowed, "https://user:pass@example.com/path", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.policy.ParseURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseURL() error = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestPolicyAllowsLocalhostOnlyForDevelopmentName(t *testing.T) {
	p := New(nil, true)
	if _, err := p.ParseURL("http://localhost:8080/path"); err != nil {
		t.Fatalf("localhost development URL rejected: %v", err)
	}
	if _, err := p.ParseURL("http://127.0.0.1:8080/path"); err != nil {
		t.Fatalf("numeric development loopback rejected: %v", err)
	}
}

func TestPolicyClientRejectsInitialSSRFURL(t *testing.T) {
	client := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false).Client(time.Second)
	_, err := client.Get("https://169.254.169.254/latest/meta-data")
	if !errors.Is(err, ErrDisallowedURL) {
		t.Fatalf("Get() error = %v, want %v", err, ErrDisallowedURL)
	}
}

func TestPolicyChecksDNSResolution(t *testing.T) {
	p := New(nil, false)
	p.resolver = lookupIPAddrFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.168.1.20")}}, nil
	})
	_, err := p.dialContext(t.Context(), "tcp", "internal.example:443")
	if !errors.Is(err, ErrDisallowedURL) {
		t.Fatalf("dialContext() error = %v, want %v", err, ErrDisallowedURL)
	}
}

func TestPolicyLocalhostNameCannotResolvePublic(t *testing.T) {
	p := New(nil, true)
	p.resolver = lookupIPAddrFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	_, err := p.dialContext(t.Context(), "tcp", "localhost:80")
	if !errors.Is(err, ErrDisallowedURL) {
		t.Fatalf("dialContext() error = %v, want %v", err, ErrDisallowedURL)
	}
}

func TestPolicyValidatesRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://169.254.169.254/private")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	_, err := New(nil, true).Client(time.Second).Get(srv.URL)
	if !errors.Is(err, ErrDisallowedURL) {
		t.Fatalf("redirect error = %v, want %v", err, ErrDisallowedURL)
	}
}

func TestPolicyDisablesEnvironmentProxy(t *testing.T) {
	if proxy := New(nil, false).transport.base.Proxy; proxy != nil {
		t.Fatal("transport proxy is set")
	}
}

type lookupIPAddrFunc func(context.Context, string) ([]net.IPAddr, error)

func (f lookupIPAddrFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}
