package crypto

import (
	"encoding/base64"
	"testing"
)

func testKey(fill byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return key
}

func TestAADBinding(t *testing.T) {
	enc := New(testKey(0xAA))
	const pt = "telegram-session-string-abc123"
	const agentA = "11111111-1111-1111-1111-111111111111"
	const agentB = "22222222-2222-2222-2222-222222222222"

	sealed, err := enc.EncryptWithAAD(pt, agentA)
	if err != nil {
		t.Fatalf("EncryptWithAAD: %v", err)
	}

	// Same aad round-trips.
	got, err := enc.DecryptWithAAD(sealed, agentA)
	if err != nil {
		t.Fatalf("DecryptWithAAD(same aad): %v", err)
	}
	if got != pt {
		t.Fatalf("round-trip = %q, want %q", got, pt)
	}

	// Different aad (another agent) must fail — this is the binding.
	if _, err := enc.DecryptWithAAD(sealed, agentB); err == nil {
		t.Error("DecryptWithAAD with a different agent's aad should fail")
	}

	// Empty aad must also fail against an aad-bound ciphertext.
	if _, err := enc.Decrypt(sealed); err == nil {
		t.Error("Decrypt (empty aad) of an aad-bound ciphertext should fail")
	}
}

func TestEmptyAADMatchesPlainEncrypt(t *testing.T) {
	enc := New(testKey(0xCD))
	const pt = "plain-config-value-987654321"

	// A value sealed with empty aad decrypts via plain Decrypt, and vice
	// versa — guarantees pre-AAD ciphertexts stay readable.
	sealed, err := enc.EncryptWithAAD(pt, "")
	if err != nil {
		t.Fatalf("EncryptWithAAD(\"\"): %v", err)
	}
	got, err := enc.Decrypt(sealed)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != pt {
		t.Fatalf("= %q, want %q", got, pt)
	}

	enc2, _ := enc.Encrypt(pt)
	if got, err := enc.DecryptWithAAD(enc2, ""); err != nil || got != pt {
		t.Fatalf("DecryptWithAAD(\"\") of Encrypt output = %q, err %v", got, err)
	}
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

func TestStableKeyIDSurvivesRingReordering(t *testing.T) {
	keyA := testKey(0xA1)
	keyB := testKey(0xB2)
	keyC := testKey(0xC3)

	enc := New(keyC, keyA, keyB)
	stored, err := enc.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	if enc.NeedsRewrap(stored) {
		t.Fatal("current ciphertext unexpectedly needs rewrap")
	}

	reordered := New(keyA, keyC, keyB)
	got, err := reordered.Decrypt(stored)
	if err != nil {
		t.Fatalf("Decrypt after key-ring reorder: %v", err)
	}
	if got != "secret" {
		t.Fatalf("Decrypt = %q, want secret", got)
	}
	if !reordered.NeedsRewrap(stored) {
		t.Fatal("ciphertext under a non-current key must need rewrap")
	}
}

func TestPositionalCiphertextRemainsDecryptable(t *testing.T) {
	oldKey := testKey(0xA4)
	newKey := testKey(0xB5)
	oldGCM := mustGCM(oldKey)
	nonce := make([]byte, oldGCM.NonceSize())
	positional := append([]byte{0}, nonce...)
	positional = append(positional, oldGCM.Seal(nil, nonce, []byte("compatibility"), nil)...)
	encoded := base64.StdEncoding.EncodeToString(positional)

	enc := New(newKey, oldKey)
	got, err := enc.Decrypt(encoded)
	if err != nil {
		t.Fatalf("Decrypt positional ciphertext: %v", err)
	}
	if got != "compatibility" {
		t.Fatalf("Decrypt positional ciphertext = %q", got)
	}
	if !enc.NeedsRewrap(encoded) {
		t.Fatal("positional ciphertext must need rewrap")
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
