package agentapi

import "testing"

func TestConnectionUpstreamURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		path    string
		want    string
		wantErr bool
	}{
		{name: "path", baseURL: "https://api.example.com/v1", path: "/devices", want: "https://api.example.com/v1/devices"},
		{name: "query", baseURL: "https://api.example.com", path: "/devices?active=true", want: "https://api.example.com/devices?active=true"},
		{name: "host suffix", baseURL: "https://api.example.com", path: ".attacker.example/steal", wantErr: true},
		{name: "missing slash", baseURL: "https://api.example.com", path: "devices", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := connectionUpstreamURL(tt.baseURL, tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("connectionUpstreamURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got.String() != tt.want {
				t.Errorf("connectionUpstreamURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
