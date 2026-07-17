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
// It also decodes the positional version-byte compatibility format.
type Encryptor struct {
	currentKeyID   string
	keys           map[string]cipher.AEAD
	positionalKeys map[byte]cipher.AEAD
}

// New creates an Encryptor. currentKey is the active encryption key (32 bytes for AES-256).
// oldKeys are previous keys that can still decrypt but won't be used for new encryptions.
// Panics if any key is not exactly 32 bytes.
func New(currentKey []byte, oldKeys ...[]byte) *Encryptor {
	e := &Encryptor{
		currentKeyID:   KeyID(currentKey),
		keys:           make(map[string]cipher.AEAD, 1+len(oldKeys)),
		positionalKeys: make(map[byte]cipher.AEAD, 1+len(oldKeys)),
	}

	// Positional ciphertext addresses keys by a one-byte version. The primary
	// format addresses keys by their stable digest ID.
	for i, key := range oldKeys {
		if i >= 255 {
			panic("crypto: too many old encryption keys")
		}
		gcm := mustGCM(key)
		e.keys[KeyID(key)] = gcm
		e.positionalKeys[byte(i)] = gcm
	}
	currentGCM := mustGCM(currentKey)
	e.keys[e.currentKeyID] = currentGCM
	e.positionalKeys[byte(len(oldKeys))] = currentGCM

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

// CurrentKeyID identifies the key used for new ciphertext.
func (e *Encryptor) CurrentKeyID() string { return e.currentKeyID }

// Encrypt encrypts plaintext into a key-ID envelope containing a nonce and
// authenticated ciphertext.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	return e.EncryptWithAAD(plaintext, "")
}

// EncryptWithAAD is Encrypt with additional authenticated data folded into the
// GCM tag. The aad is authenticated but NOT encrypted; decryption only
// succeeds when DecryptWithAAD is given the identical aad. Used to bind a
// ciphertext to a context (e.g. an agent ID) so it can't be decrypted under a
// different context. aad="" is byte-identical to Encrypt (no binding).
func (e *Encryptor) EncryptWithAAD(plaintext, aad string) (string, error) {
	gcm := e.keys[e.currentKeyID]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), aadBytes(aad))

	buf := make([]byte, 0, len(nonce)+len(ciphertext))
	buf = append(buf, nonce...)
	buf = append(buf, ciphertext...)

	return ciphertextPrefix + e.currentKeyID + ":" + base64.RawStdEncoding.EncodeToString(buf), nil
}

// Decrypt decodes a base64-encoded string and decrypts it using the key
// identified by the version byte prefix.
func (e *Encryptor) Decrypt(encoded string) (string, error) {
	return e.DecryptWithAAD(encoded, "")
}

// DecryptWithAAD is Decrypt for ciphertext produced by EncryptWithAAD. It
// returns an error when aad doesn't match the value used at encryption time
// (the GCM auth tag fails to verify) — that mismatch is the binding guarantee.
func (e *Encryptor) DecryptWithAAD(encoded, aad string) (string, error) {
	if strings.HasPrefix(encoded, ciphertextPrefix) {
		return e.decryptStable(encoded, aad)
	}
	return e.decryptPositional(encoded, aad)
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

func (e *Encryptor) decryptPositional(encoded, aad string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	if len(raw) < 1 {
		return "", fmt.Errorf("ciphertext too short")
	}

	version := raw[0]
	gcm, ok := e.positionalKeys[version]
	if !ok {
		return "", fmt.Errorf("unknown key version %d", version)
	}

	return open(gcm, raw[1:], aad)
}

func open(gcm cipher.AEAD, raw []byte, aad string) (string, error) {
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short for nonce")
	}
	plaintext, err := gcm.Open(nil, raw[:nonceSize], raw[nonceSize:], aadBytes(aad))
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// NeedsRewrap reports whether encoded uses the positional format or a non-current
// key. It validates only the envelope; Rewrap callers still authenticate it by
// decrypting before replacing persisted data.
func (e *Encryptor) NeedsRewrap(encoded string) bool {
	if !strings.HasPrefix(encoded, ciphertextPrefix) {
		return true
	}
	rest := strings.TrimPrefix(encoded, ciphertextPrefix)
	keyID, _, ok := strings.Cut(rest, ":")
	return !ok || keyID != e.currentKeyID
}

// aadBytes maps an empty AAD to nil. GCM treats nil and empty additional data
// identically, and the positional compatibility format uses nil.
func aadBytes(aad string) []byte {
	if aad == "" {
		return nil
	}
	return []byte(aad)
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
