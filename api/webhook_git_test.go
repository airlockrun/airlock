package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestVerifyGitHubSignature(t *testing.T) {
	secret := "the-per-agent-secret"
	body := []byte(`{"ref":"refs/heads/main"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name    string
		header  string
		secret  string
		body    []byte
		wantErr string
	}{
		{name: "correct signature", header: good, secret: secret, body: body, wantErr: ""},
		{name: "wrong secret", header: good, secret: "wrong-secret", body: body, wantErr: "mismatch"},
		{name: "tampered body", header: good, secret: secret, body: []byte(`{"ref":"refs/heads/main","bad":1}`), wantErr: "mismatch"},
		{name: "missing prefix", header: hex.EncodeToString(mac.Sum(nil)), secret: secret, body: body, wantErr: "prefix"},
		{name: "garbage hex", header: "sha256=not-hex", secret: secret, body: body, wantErr: "encoding/hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyGitHubSignature(tt.body, tt.header, tt.secret)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("verifyGitHubSignature: unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("verifyGitHubSignature: want error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("verifyGitHubSignature error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
