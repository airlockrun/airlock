package agentapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

var (
	errPrivateNetworkURL = errors.New("url must resolve to a public address")
	cgnatPrefix          = netip.MustParsePrefix("100.64.0.0/10")
	publicHTTPTransport  = newPublicHTTPTransport()
)

func newPublicHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: publicHTTPTransport}
}

func newPublicHTTPTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = publicOnlyDialContext
	return tr
}

func parsePublicHTTPURL(raw string) (*url.URL, error) {
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
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !isPublicAddr(ip) {
		return nil, errPrivateNetworkURL
	}
	return u, nil
}

func publicOnlyDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
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
		if !isPublicAddr(addr) {
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
		return nil, errPrivateNetworkURL
	}
	return nil, fmt.Errorf("no usable addresses for %s", host)
}

func isPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() &&
		addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsMulticast() &&
		!addr.IsUnspecified() &&
		!cgnatPrefix.Contains(addr)
}
