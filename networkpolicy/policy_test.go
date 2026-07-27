package networkpolicy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
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
		{"private HTTP remains blocked", privateAllowed, "http://10.0.0.1/path", true},
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

func TestProviderEndpointClientPolicy(t *testing.T) {
	privateCIDRs := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	tests := []struct {
		name    string
		policy  *Policy
		raw     string
		wantErr bool
	}{
		{name: "private HTTP allowed", policy: New(privateCIDRs, false), raw: "http://10.20.30.40:11434/v1", wantErr: false},
		{name: "private HTTPS allowed", policy: New(privateCIDRs, false), raw: "https://10.20.30.40/v1", wantErr: false},
		{name: "public HTTP rejected", policy: New(privateCIDRs, false), raw: "http://93.184.216.34/v1", wantErr: true},
		{name: "public HTTPS accepted", policy: New(privateCIDRs, false), raw: "https://93.184.216.34/v1", wantErr: false},
		{name: "metadata HTTP rejected", policy: New([]netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}, false), raw: "http://169.254.169.254/latest/meta-data", wantErr: true},
		{name: "metadata HTTPS rejected", policy: New([]netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}, false), raw: "https://169.254.169.254/latest/meta-data", wantErr: true},
		{name: "loopback rejected despite CIDR", policy: New([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, false), raw: "http://127.0.0.1:11434/v1", wantErr: true},
		{name: "non-allowlisted private HTTP rejected", policy: New(privateCIDRs, false), raw: "http://192.168.1.20:11434/v1", wantErr: true},
		{name: "multicast HTTP rejected despite CIDR", policy: New([]netip.Prefix{netip.MustParsePrefix("224.0.0.0/4")}, false), raw: "http://224.0.0.1/v1", wantErr: true},
		{name: "unspecified HTTP rejected despite CIDR", policy: New([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/8")}, false), raw: "http://0.0.0.0:11434/v1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.policy.parseProviderEndpointURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseProviderEndpointURL() error = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestProviderEndpointClientAllowsPublicHTTPSAtDialTime(t *testing.T) {
	p := New(nil, false)
	p.resolver = lookupIPAddrFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	wantErr := errors.New("public HTTPS reached dialer")
	var dialed string
	p.dialer = dialContextFunc(func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = address
		return nil, wantErr
	})

	_, err := p.ProviderEndpointClient(time.Second).Get("https://public.example/v1/models")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Get() error = %v, want dialer error", err)
	}
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed address = %q", dialed)
	}
}

func TestProviderEndpointClientAllowsPrivateHTTPAtDialTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	p := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false)
	p.resolver = lookupIPAddrFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "model.internal" {
			t.Fatalf("resolved host = %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("10.20.30.40")}}, nil
	})
	var dialed string
	p.dialer = dialContextFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		return (&net.Dialer{}).DialContext(ctx, network, serverURL.Host)
	})

	resp, err := p.ProviderEndpointClient(time.Second).Get("http://model.internal:" + serverURL.Port() + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if dialed != net.JoinHostPort("10.20.30.40", serverURL.Port()) {
		t.Fatalf("dialed address = %q", dialed)
	}
}

func TestProviderEndpointClientRejectsPublicHTTPAtDialTime(t *testing.T) {
	p := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false)
	p.resolver = lookupIPAddrFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	dialed := false
	p.dialer = dialContextFunc(func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unexpected dial")
	})

	_, err := p.ProviderEndpointClient(time.Second).Get("http://public.example/v1/models")
	if !errors.Is(err, ErrDisallowedURL) {
		t.Fatalf("Get() error = %v, want %v", err, ErrDisallowedURL)
	}
	if dialed {
		t.Fatal("public HTTP address was dialed")
	}
}

func TestProviderEndpointClientFiltersEveryDNSResult(t *testing.T) {
	p := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false)
	p.resolver = lookupIPAddrFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("169.254.169.254")},
			{IP: net.ParseIP("93.184.216.34")},
			{IP: net.ParseIP("10.8.0.12")},
		}, nil
	})
	wantErr := errors.New("allowed address reached dialer")
	var dialed []string
	p.dialer = dialContextFunc(func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, wantErr
	})

	_, err := p.ProviderEndpointClient(time.Second).Get("http://rebind.example:11434/v1/models")
	if !errors.Is(err, wantErr) {
		t.Fatalf("Get() error = %v, want dialer error", err)
	}
	if got := strings.Join(dialed, ","); got != "10.8.0.12:11434" {
		t.Fatalf("dialed addresses = %q, want only allowlisted private address", got)
	}
}

func TestProviderEndpointClientRechecksDNSOnNewDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	p := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false)
	lookups := 0
	p.resolver = lookupIPAddrFunc(func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		if lookups == 1 {
			return []net.IPAddr{{IP: net.ParseIP("10.20.30.40")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	})
	dials := 0
	p.dialer = dialContextFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials++
		return (&net.Dialer{}).DialContext(ctx, network, serverURL.Host)
	})
	client := p.ProviderEndpointClient(time.Second)
	endpoint := "http://rebind.example:" + serverURL.Port() + "/v1/models"

	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	client.CloseIdleConnections()

	_, err = client.Get(endpoint)
	if !errors.Is(err, ErrDisallowedURL) {
		t.Fatalf("second Get() error = %v, want %v", err, ErrDisallowedURL)
	}
	if lookups != 2 {
		t.Fatalf("DNS lookups = %d, want 2", lookups)
	}
	if dials != 1 {
		t.Fatalf("dial attempts = %d, want only the first allowed resolution", dials)
	}
}

func TestProviderEndpointClientRejectsRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer server.Close()

	_, err := New(nil, true).ProviderEndpointClient(time.Second).Get(server.URL)
	if err == nil || !strings.Contains(err.Error(), "redirects are not allowed") {
		t.Fatalf("Get() error = %v, want redirect rejection", err)
	}
}

type lookupIPAddrFunc func(context.Context, string) ([]net.IPAddr, error)

func (f lookupIPAddrFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func (f dialContextFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}
