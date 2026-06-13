// Package secrets provides a forward-compatible interface for secret storage.
//
// All API keys, OAuth tokens, webhook secrets, and other credential material
// flows through Store. The current implementation (LocalStore) wraps the
// in-process AES-256-GCM crypto package and stores ciphertext inline in
// resource columns. A future enterprise build can swap in a Vault-backed
// implementation without touching call sites.
//
// The ref argument on every method names the secret with a path-like
// identifier — e.g. "connection/<id>/access_token". LocalStore ignores it
// (the ciphertext is self-contained), but call sites should pass a stable,
// unique ref so a future remote store can route to the correct location.
package secrets

import (
	"context"

	"github.com/airlockrun/airlock/crypto"
)

// Store is the interface for storing and retrieving secret material.
type Store interface {
	// Put encrypts plaintext and returns a value the caller persists
	// alongside the owning resource row. The returned value is opaque to
	// callers — its format depends on the implementation.
	Put(ctx context.Context, ref, plaintext string) (string, error)

	// Get returns the plaintext given a value previously returned by Put.
	Get(ctx context.Context, ref, stored string) (string, error)

	// Seal encrypts plaintext bound to aad and returns an opaque sealed
	// value. Open returns the plaintext only when given the identical aad —
	// the binding lets the agent persist the sealed value in its own storage
	// while a caller under a different aad cannot decrypt it. (For LocalStore
	// the aad is the GCM additional-authenticated-data; a future KMS store
	// maps it to the encryption context.)
	Seal(ctx context.Context, aad, plaintext string) (string, error)

	// Open reverses Seal. Returns an error if aad doesn't match the value
	// sealed under.
	Open(ctx context.Context, aad, sealed string) (string, error)
}

// LocalStore implements Store using AES-256-GCM with versioned keys.
// ref is accepted for API symmetry but ignored — the ciphertext blob is
// self-contained.
type LocalStore struct {
	enc *crypto.Encryptor
}

// NewLocal wraps a crypto.Encryptor as a Store. enc must be non-nil.
func NewLocal(enc *crypto.Encryptor) *LocalStore {
	if enc == nil {
		panic("secrets: NewLocal requires a non-nil *crypto.Encryptor")
	}
	return &LocalStore{enc: enc}
}

func (l *LocalStore) Put(_ context.Context, _, plaintext string) (string, error) {
	return l.enc.Encrypt(plaintext)
}

func (l *LocalStore) Get(_ context.Context, _, stored string) (string, error) {
	return l.enc.Decrypt(stored)
}

func (l *LocalStore) Seal(_ context.Context, aad, plaintext string) (string, error) {
	return l.enc.EncryptWithAAD(plaintext, aad)
}

func (l *LocalStore) Open(_ context.Context, aad, sealed string) (string, error) {
	return l.enc.DecryptWithAAD(sealed, aad)
}
