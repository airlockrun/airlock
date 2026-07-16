package auth

import (
	"bytes"
	"testing"
)

func TestIntegrationTokenRoundTrip(t *testing.T) {
	token, stored, err := NewIntegrationToken()
	if err != nil {
		t.Fatalf("NewIntegrationToken() error: %v", err)
	}
	if token == "" {
		t.Fatal("NewIntegrationToken() returned an empty token")
	}
	if got := HashIntegrationToken(token); !bytes.Equal(got, stored) {
		t.Fatalf("HashIntegrationToken(token) = %x, want %x", got, stored)
	}
	if got := HashIntegrationToken(token + "x"); got != nil {
		t.Fatalf("HashIntegrationToken(tampered) = %x, want nil", got)
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{name: "valid", header: "Bearer token", want: "token", ok: true},
		{name: "missing", header: ""},
		{name: "wrong scheme", header: "Basic token"},
		{name: "whitespace", header: "Bearer two tokens"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BearerToken(tt.header)
			if (err == nil) != tt.ok {
				t.Fatalf("BearerToken(%q) error = %v, want ok=%v", tt.header, err, tt.ok)
			}
			if got != tt.want {
				t.Errorf("BearerToken(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}
