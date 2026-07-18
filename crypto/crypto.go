// Package crypto provides AES-256-GCM encryption with versioned keys for rotation.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const ciphertextPrefix = "airlock-crypto:v2:"

// Encryptor encrypts and decrypts data using AES-256-GCM with stable key IDs.
type Encryptor struct {
	currentKeyID string
	keys         map[string]cipher.AEAD
}

// New creates an Encryptor. currentKey is the active encryption key (32 bytes for AES-256).
// oldKeys are previous keys that can still decrypt but won't be used for new encryptions.
// Panics if any key is not exactly 32 bytes.
func New(currentKey []byte, oldKeys ...[]byte) *Encryptor {
	e := &Encryptor{
		currentKeyID: KeyID(currentKey),
		keys:         make(map[string]cipher.AEAD, 1+len(oldKeys)),
	}

	for _, key := range oldKeys {
		e.keys[KeyID(key)] = mustGCM(key)
	}
	e.keys[e.currentKeyID] = mustGCM(currentKey)

	return e
}

// KeyID returns a stable, non-secret identifier for a key. The truncated
// SHA-256 digest remains the same regardless of key-ring ordering.
func KeyID(key []byte) string {
	if len(key) != 32 {
		panic(fmt.Sprintf("encryption key must be 32 bytes, got %d", len(key)))
	}
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:16])
}

// EncryptWithAAD encrypts plaintext into a key-ID envelope containing a nonce
// and authenticated ciphertext. The aad is authenticated but NOT encrypted;
// decryption only succeeds when DecryptWithAAD is given the identical aad. Used
// to bind ciphertext to a context so it cannot be decrypted under another one.
func (e *Encryptor) EncryptWithAAD(plaintext, aad string) (string, error) {
	if aad == "" {
		return "", errors.New("additional authenticated data is required")
	}
	gcm := e.keys[e.currentKeyID]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), []byte(aad))

	buf := make([]byte, 0, len(nonce)+len(ciphertext))
	buf = append(buf, nonce...)
	buf = append(buf, ciphertext...)

	return ciphertextPrefix + e.currentKeyID + ":" + base64.RawStdEncoding.EncodeToString(buf), nil
}

// DecryptWithAAD decrypts ciphertext produced by EncryptWithAAD. It returns an
// error when aad doesn't match the value used at encryption time (the GCM auth
// tag fails to verify) — that mismatch is the binding guarantee.
func (e *Encryptor) DecryptWithAAD(encoded, aad string) (string, error) {
	if aad == "" {
		return "", errors.New("additional authenticated data is required")
	}
	if !strings.HasPrefix(encoded, ciphertextPrefix) {
		return "", errors.New("invalid ciphertext envelope")
	}
	return e.decryptStable(encoded, aad)
}

func (e *Encryptor) decryptStable(encoded, aad string) (string, error) {
	rest := strings.TrimPrefix(encoded, ciphertextPrefix)
	keyID, payload, ok := strings.Cut(rest, ":")
	if !ok || keyID == "" || payload == "" {
		return "", errors.New("invalid ciphertext envelope")
	}
	gcm, ok := e.keys[keyID]
	if !ok {
		return "", fmt.Errorf("unknown key ID %q", keyID)
	}
	raw, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	return open(gcm, raw, aad)
}

func open(gcm cipher.AEAD, raw []byte, aad string) (string, error) {
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short for nonce")
	}
	plaintext, err := gcm.Open(nil, raw[:nonceSize], raw[nonceSize:], []byte(aad))
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// NeedsRewrap reports whether encoded uses a non-current key. It validates only
// the envelope; Rewrap callers still authenticate it by decrypting before
// replacing persisted data.
func (e *Encryptor) NeedsRewrap(encoded string) bool {
	if !strings.HasPrefix(encoded, ciphertextPrefix) {
		return true
	}
	rest := strings.TrimPrefix(encoded, ciphertextPrefix)
	keyID, _, ok := strings.Cut(rest, ":")
	return !ok || keyID != e.currentKeyID
}

func mustGCM(key []byte) cipher.AEAD {
	if len(key) != 32 {
		panic(fmt.Sprintf("encryption key must be 32 bytes, got %d", len(key)))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("aes.NewCipher: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("cipher.NewGCM: %v", err))
	}
	return gcm
}
