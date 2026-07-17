// Package networkpolicy provides the outbound HTTP transport used for
// user-configured destinations.
package networkpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var (
	ErrDisallowedURL   = errors.New("URL must resolve to an allowed address")
	publicSpecialAddrs = map[netip.Addr]struct{}{
		netip.MustParseAddr("192.0.0.9"): {}, netip.MustParseAddr("192.0.0.10"): {},
		netip.MustParseAddr("192.88.99.2"): {},
	}
	nonPublicPrefixes = mustParsePrefixes(
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"240.0.0.0/4", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64",
		"2001:2::/48", "2001:10::/28", "2001:db8::/32", "2002::/16",
		"3fff::/20", "5f00::/16",
	)
)

type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Policy validates URLs and supplies clients backed by one shared transport.
type Policy struct {
	privateCIDRs   []netip.Prefix
	allowLocalhost bool
	resolver       ipResolver
	transport      *policyTransport
}

// New constructs an outbound policy. allowLocalhost is only for development
// instances whose configured public URL is itself localhost.
func New(privateCIDRs []netip.Prefix, allowLocalhost bool) *Policy {
	p := &Policy{
		privateCIDRs:   append([]netip.Prefix(nil), privateCIDRs...),
		allowLocalhost: allowLocalhost,
		resolver:       net.DefaultResolver,
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.DialContext = p.dialContext
	p.transport = &policyTransport{policy: p, base: base}
	return p
}

type policyTransport struct {
	policy *Policy
	base   *http.Transport
}

func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, err := t.policy.ParseURL(req.URL.String()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// AllowsLocalhostDevelopment reports whether publicURL explicitly configures
// a localhost HTTP development instance.
func AllowsLocalhostDevelopment(publicURL string) bool {
	u, err := url.Parse(publicURL)
	return err == nil && u.Scheme == "http" && isLocalhostHost(u.Hostname())
}

// Client returns an HTTP client backed by the policy's shared transport.
func (p *Policy) Client(timeout time.Duration) *http.Client {
	if p == nil {
		panic("networkpolicy: policy is required")
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: p.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if _, err := p.ParseURL(req.URL.String()); err != nil {
				return err
			}
			if len(via) > 0 && !SameOrigin(via[0].URL, req.URL) {
				return errors.New("cross-origin redirect is not allowed")
			}
			return nil
		},
	}
}

// ParseURL validates the non-DNS properties of an outbound URL. DNS is
// resolved again by the transport immediately before dialing.
func (p *Policy) ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("host is required")
	}
	if u.User != nil {
		return nil, errors.New("userinfo is not allowed")
	}
	localhost := isLocalhostHost(u.Hostname())
	if u.Scheme != "https" && !(p.allowLocalhost && localhost) {
		return nil, errors.New("HTTPS is required")
	}
	if localhost && !p.allowLocalhost {
		return nil, ErrDisallowedURL
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !p.allowsAddr(ip, localhost) {
		return nil, ErrDisallowedURL
	}
	return u, nil
}

// SameOrigin compares URL scheme, hostname, and effective port.
func SameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func (p *Policy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	localhost := isLocalhostHost(host)
	if localhost && !p.allowLocalhost {
		return nil, ErrDisallowedURL
	}
	resolved, err := p.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	var dialErr error
	for _, ipAddr := range resolved {
		addr, ok := netip.AddrFromSlice(ipAddr.IP)
		if !ok || !p.allowsAddr(addr.Unmap(), localhost) {
			continue
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(addr.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		dialErr = err
	}
	if dialErr != nil {
		return nil, dialErr
	}
	return nil, ErrDisallowedURL
}

func (p *Policy) allowsAddr(addr netip.Addr, localhostName bool) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if localhostName {
		return p.allowLocalhost && addr.IsLoopback()
	}
	if addr.IsLoopback() {
		return false
	}
	if isPublicAddr(addr) {
		return true
	}
	for _, prefix := range p.privateCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isLocalhostName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

func isLocalhostHost(host string) bool {
	if isLocalhostName(host) {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func isPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if _, ok := publicSpecialAddrs[addr]; ok {
		return true
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func mustParsePrefixes(raw ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(raw))
	for i, value := range raw {
		prefixes[i] = netip.MustParsePrefix(value)
	}
	return prefixes
}
