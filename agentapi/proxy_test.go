package agentapi

import (
	"net/netip"
	"testing"

	"github.com/airlockrun/airlock/networkpolicy"
)

func TestConnectionUpstreamURL(t *testing.T) {
	policy := networkpolicy.New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, false)
	tests := []struct {
		name    string
		baseURL string
		path    string
		want    string
		wantErr bool
	}{
		{name: "path", baseURL: "https://api.example.com/v1", path: "/devices", want: "https://api.example.com/v1/devices"},
		{name: "query", baseURL: "https://api.example.com", path: "/devices?active=true", want: "https://api.example.com/devices?active=true"},
		{name: "allowed private target", baseURL: "https://10.1.2.3/api", path: "/devices", want: "https://10.1.2.3/api/devices"},
		{name: "private target outside allowlist", baseURL: "https://192.168.1.1", path: "/devices", wantErr: true},
		{name: "loopback target", baseURL: "https://127.0.0.1", path: "/devices", wantErr: true},
		{name: "host suffix", baseURL: "https://api.example.com", path: ".attacker.example/steal", wantErr: true},
		{name: "missing slash", baseURL: "https://api.example.com", path: "devices", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := connectionUpstreamURL(policy, tt.baseURL, tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("connectionUpstreamURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got.String() != tt.want {
				t.Errorf("connectionUpstreamURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
