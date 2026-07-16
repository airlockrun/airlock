package agentapi

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
	errDisallowedNetworkURL = errors.New("url must resolve to an allowed address")
	publicSpecialAddrs      = map[netip.Addr]struct{}{
		netip.MustParseAddr("192.0.0.9"):   {},
		netip.MustParseAddr("192.0.0.10"):  {},
		netip.MustParseAddr("192.88.99.2"): {},
	}
	nonPublicPrefixes = mustParsePrefixes(
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		"64:ff9b:1::/48",
		"100::/64",
		"100:0:0:1::/64",
		"2001:2::/48",
		"2001:10::/28",
		"2001:db8::/32",
		"2002::/16",
		"3fff::/20",
		"5f00::/16",
	)
)

type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type httpNetworkPolicy struct {
	privateCIDRs []netip.Prefix
	resolver     ipResolver
	transport    *http.Transport
}

func newHTTPNetworkPolicy(privateCIDRs []netip.Prefix) *httpNetworkPolicy {
	p := &httpNetworkPolicy{
		privateCIDRs: append([]netip.Prefix(nil), privateCIDRs...),
		resolver:     net.DefaultResolver,
	}
	p.transport = http.DefaultTransport.(*http.Transport).Clone()
	p.transport.Proxy = nil
	p.transport.DialContext = p.dialContext
	return p
}

func (p *httpNetworkPolicy) client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: p.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && !sameHTTPOrigin(via[0].URL, req.URL) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func sameHTTPOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
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

func (p *httpNetworkPolicy) parseHTTPURL(raw string) (*url.URL, error) {
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
	if isLocalhostName(u.Hostname()) {
		return nil, errDisallowedNetworkURL
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !p.allowsAddr(ip) {
		return nil, errDisallowedNetworkURL
	}
	return u, nil
}

func (p *httpNetworkPolicy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if isLocalhostName(host) {
		return nil, errDisallowedNetworkURL
	}
	resolved, err := p.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	var blocked bool
	dialer := &net.Dialer{}
	for _, ipAddr := range resolved {
		addr, ok := netip.AddrFromSlice(ipAddr.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !p.allowsAddr(addr) {
			blocked = true
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	if err != nil {
		return nil, err
	}
	if blocked {
		return nil, errDisallowedNetworkURL
	}
	return nil, fmt.Errorf("no usable addresses for %s", host)
}

func isLocalhostName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

func (p *httpNetworkPolicy) allowsAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
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

func isPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() ||
		!addr.IsGlobalUnicast() ||
		addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
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
