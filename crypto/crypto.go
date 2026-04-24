// Package crypto provides AES-256-GCM encryption with versioned keys for rotation.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Encryptor encrypts and decrypts data using AES-256-GCM with versioned keys.
// The version byte prefix allows decryption with old keys during rotation.
type Encryptor struct {
	currentVersion byte
	keys           map[byte]cipher.AEAD // version → GCM cipher
}

// New creates an Encryptor. currentKey is the active encryption key (32 bytes for AES-256).
// oldKeys are previous keys that can still decrypt but won't be used for new encryptions.
// Panics if any key is not exactly 32 bytes.
func New(currentKey []byte, oldKeys ...[]byte) *Encryptor {
	e := &Encryptor{
		keys: make(map[byte]cipher.AEAD, 1+len(oldKeys)),
	}

	// Old keys get versions 0, 1, 2, ... in order provided
	for i, key := range oldKeys {
		version := byte(i)
		e.keys[version] = mustGCM(key)
	}

	// Current key gets the next version
	e.currentVersion = byte(len(oldKeys))
	e.keys[e.currentVersion] = mustGCM(currentKey)

	return e
}

// Encrypt encrypts plaintext and returns a base64-encoded string containing:
// version byte + nonce + ciphertext.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	gcm := e.keys[e.currentVersion]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Encode: version + nonce + ciphertext
	buf := make([]byte, 0, 1+len(nonce)+len(ciphertext))
	buf = append(buf, e.currentVersion)
	buf = append(buf, nonce...)
	buf = append(buf, ciphertext...)

	return base64.StdEncoding.EncodeToString(buf), nil
}

// Decrypt decodes a base64-encoded string and decrypts it using the key
// identified by the version byte prefix.
func (e *Encryptor) Decrypt(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	if len(raw) < 1 {
		return "", fmt.Errorf("ciphertext too short")
	}

	version := raw[0]
	gcm, ok := e.keys[version]
	if !ok {
		return "", fmt.Errorf("unknown key version %d", version)
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < 1+nonceSize {
		return "", fmt.Errorf("ciphertext too short for nonce")
	}

	nonce := raw[1 : 1+nonceSize]
	ciphertext := raw[1+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
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
