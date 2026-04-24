package crypto

import (
	"testing"
)

func testKey(fill byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return key
}

func TestRoundTrip(t *testing.T) {
	enc := New(testKey(0xAA))
	plaintext := "sk-secret-api-key-12345"

	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if encrypted == plaintext {
		t.Fatal("encrypted should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}

func TestKeyRotation(t *testing.T) {
	oldKey := testKey(0xAA)
	newKey := testKey(0xBB)

	// Encrypt with old key
	oldEnc := New(oldKey)
	encrypted, err := oldEnc.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt with old key: %v", err)
	}

	// Create new encryptor with rotated keys
	newEnc := New(newKey, oldKey)

	// Should decrypt old ciphertext
	decrypted, err := newEnc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt old ciphertext with new encryptor: %v", err)
	}
	if decrypted != "secret" {
		t.Errorf("got %q, want %q", decrypted, "secret")
	}

	// New encryptions use new key
	encrypted2, err := newEnc.Encrypt("new-secret")
	if err != nil {
		t.Fatalf("Encrypt with new key: %v", err)
	}

	decrypted2, err := newEnc.Decrypt(encrypted2)
	if err != nil {
		t.Fatalf("Decrypt new ciphertext: %v", err)
	}
	if decrypted2 != "new-secret" {
		t.Errorf("got %q, want %q", decrypted2, "new-secret")
	}

	// Old encryptor cannot decrypt new ciphertext (unknown version)
	_, err = oldEnc.Decrypt(encrypted2)
	if err == nil {
		t.Error("expected error decrypting new ciphertext with old encryptor")
	}
}

func TestBadKeyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for bad key length")
		}
	}()
	New([]byte("too-short"))
}

func TestEmptyPlaintext(t *testing.T) {
	enc := New(testKey(0xCC))

	encrypted, err := enc.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if decrypted != "" {
		t.Errorf("got %q, want empty string", decrypted)
	}
}

func TestDecryptBadInput(t *testing.T) {
	enc := New(testKey(0xDD))

	// Not base64
	_, err := enc.Decrypt("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for non-base64 input")
	}

	// Too short
	_, err = enc.Decrypt("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestDifferentPlaintextsProduceDifferentCiphertexts(t *testing.T) {
	enc := New(testKey(0xEE))

	a, _ := enc.Encrypt("alpha")
	b, _ := enc.Encrypt("beta")

	if a == b {
		t.Error("different plaintexts should produce different ciphertexts")
	}

	// Same plaintext encrypted twice should also differ (random nonce)
	c, _ := enc.Encrypt("alpha")
	if a == c {
		t.Error("same plaintext encrypted twice should produce different ciphertexts")
	}
}
