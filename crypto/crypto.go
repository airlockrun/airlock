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
	return e.EncryptWithAAD(plaintext, "")
}

// EncryptWithAAD is Encrypt with additional authenticated data folded into the
// GCM tag. The aad is authenticated but NOT encrypted; decryption only
// succeeds when DecryptWithAAD is given the identical aad. Used to bind a
// ciphertext to a context (e.g. an agent ID) so it can't be decrypted under a
// different context. aad="" is byte-identical to Encrypt (no binding).
func (e *Encryptor) EncryptWithAAD(plaintext, aad string) (string, error) {
	gcm := e.keys[e.currentVersion]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), aadBytes(aad))

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
	return e.DecryptWithAAD(encoded, "")
}

// DecryptWithAAD is Decrypt for ciphertext produced by EncryptWithAAD. It
// returns an error when aad doesn't match the value used at encryption time
// (the GCM auth tag fails to verify) — that mismatch is the binding guarantee.
func (e *Encryptor) DecryptWithAAD(encoded, aad string) (string, error) {
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

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aadBytes(aad))
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// aadBytes maps an empty aad to a nil slice so Encrypt/Decrypt (aad="")
// produce and accept exactly the same ciphertext as before AAD support — GCM
// treats nil and empty additionalData identically, but nil keeps pre-AAD
// ciphertexts decryptable and the intent explicit.
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
