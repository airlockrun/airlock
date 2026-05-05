package api

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
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

func TestVerifyBearer(t *testing.T) {
	secret := "shh-its-a-secret"

	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{"valid", "Bearer shh-its-a-secret", true},
		{"lowercase scheme", "bearer shh-its-a-secret", true},
		{"wrong token", "Bearer nope", false},
		{"missing scheme", "shh-its-a-secret", false},
		{"empty", "", false},
		{"basic instead", "Basic dXNlcjpwYXNz", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := verifyBearer(secret, tc.header)
			if got != tc.want {
				t.Errorf("verifyBearer(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

func TestVerifyEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)
	body := []byte(`{"hello":"world"}`)
	now := time.Unix(1_700_000_000, 0)
	tsStr := strconv.FormatInt(now.Unix(), 10)

	signed := append([]byte(tsStr), body...)
	sig := ed25519.Sign(priv, signed)
	sigHex := hex.EncodeToString(sig)

	t.Run("valid", func(t *testing.T) {
		if !verifyEd25519(pubHex, body, sigHex, tsStr, now) {
			t.Error("expected valid signature to pass")
		}
	})

	t.Run("tampered body", func(t *testing.T) {
		if verifyEd25519(pubHex, []byte(`{"hello":"mars"}`), sigHex, tsStr, now) {
			t.Error("expected tampered body to fail")
		}
	})

	t.Run("tampered timestamp", func(t *testing.T) {
		if verifyEd25519(pubHex, body, sigHex, strconv.FormatInt(now.Unix()+1, 10), now) {
			t.Error("expected tampered timestamp to fail")
		}
	})

	t.Run("skew too large", func(t *testing.T) {
		if verifyEd25519(pubHex, body, sigHex, tsStr, now.Add(10*time.Minute)) {
			t.Error("expected stale signature to fail")
		}
	})

	t.Run("skew within window", func(t *testing.T) {
		if !verifyEd25519(pubHex, body, sigHex, tsStr, now.Add(2*time.Minute)) {
			t.Error("expected within-window skew to pass")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		if verifyEd25519(hex.EncodeToString(other), body, sigHex, tsStr, now) {
			t.Error("expected wrong public key to fail")
		}
	})

	t.Run("malformed pubkey", func(t *testing.T) {
		if verifyEd25519("not-hex", body, sigHex, tsStr, now) {
			t.Error("expected malformed pubkey to fail")
		}
	})

	t.Run("missing headers", func(t *testing.T) {
		if verifyEd25519(pubHex, body, "", tsStr, now) {
			t.Error("expected missing signature to fail")
		}
		if verifyEd25519(pubHex, body, sigHex, "", now) {
			t.Error("expected missing timestamp to fail")
		}
	})
}
