package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/secrets"
)

func TestGitWebhookSecretCompatibility(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	store := secrets.NewLocal(crypto.New(key))
	const ref = "agent/00000000-0000-0000-0000-000000000001/git_webhook_secret"

	got, err := gitWebhookSecret(ctx, store, ref, "plain-secret")
	if err != nil || got != "plain-secret" {
		t.Fatalf("plaintext git webhook secret = %q, %v", got, err)
	}
	if _, err := store.Get(ctx, ref, "plain-secret"); err == nil {
		t.Fatal("generic secret read accepted plaintext")
	}

	stored, err := store.Put(ctx, ref, "enveloped-secret")
	if err != nil {
		t.Fatal(err)
	}
	got, err = gitWebhookSecret(ctx, store, ref, stored)
	if err != nil || got != "enveloped-secret" {
		t.Fatalf("enveloped git webhook secret = %q, %v", got, err)
	}
	if _, err := gitWebhookSecret(ctx, store, "wrong-ref", stored); err == nil {
		t.Fatal("enveloped git webhook secret accepted wrong ref")
	}
}

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
