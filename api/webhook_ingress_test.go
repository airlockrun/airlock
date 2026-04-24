package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyHMAC(t *testing.T) {
	secret := []byte("test-secret-key")
	body := []byte(`{"action":"opened"}`)

	// Compute expected signature.
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	t.Run("valid raw hex", func(t *testing.T) {
		if !verifyHMAC(secret, body, sig) {
			t.Error("expected valid signature to pass")
		}
	})

	t.Run("valid with sha256= prefix", func(t *testing.T) {
		if !verifyHMAC(secret, body, "sha256="+sig) {
			t.Error("expected sha256= prefixed signature to pass")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		if verifyHMAC(secret, body, "sha256=deadbeef") {
			t.Error("expected invalid signature to fail")
		}
	})

	t.Run("empty header", func(t *testing.T) {
		if verifyHMAC(secret, body, "") {
			t.Error("expected empty header to fail")
		}
	})

	t.Run("wrong body", func(t *testing.T) {
		if verifyHMAC(secret, []byte("wrong body"), sig) {
			t.Error("expected wrong body to fail")
		}
	})
}

func TestVerifyToken(t *testing.T) {
	secret := "my-webhook-secret-token"

	t.Run("valid token", func(t *testing.T) {
		if !verifyToken(secret, secret) {
			t.Error("expected matching token to pass")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		if verifyToken(secret, "wrong-token") {
			t.Error("expected non-matching token to fail")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		if verifyToken(secret, "") {
			t.Error("expected empty token to fail")
		}
	})
}
