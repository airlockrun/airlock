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
