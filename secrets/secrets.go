// Package secrets provides a forward-compatible interface for secret storage.
//
// All API keys, OAuth tokens, webhook secrets, and other credential material
// flows through Store. The current implementation (LocalStore) wraps the
// in-process AES-256-GCM crypto package and stores ciphertext inline in
// resource columns. A future enterprise build can swap in a Vault-backed
// implementation without touching call sites.
//
// The ref argument on every method names the secret with a stable path-like
// identifier, e.g. "connection/<id>/access_token". LocalStore authenticates
// the ref as AES-GCM additional data, preventing ciphertext from being moved
// between resource fields.
package secrets

import (
	"context"
	"errors"
	"strings"

	"github.com/airlockrun/airlock/crypto"
)

const localEnvelopePrefix = "airlock-secret:v1:"

// Store is the interface for storing and retrieving secret material.
type Store interface {
	// Put encrypts plaintext and returns a value the caller persists
	// alongside the owning resource row. The returned value is opaque to
	// callers — its format depends on the implementation.
	Put(ctx context.Context, ref, plaintext string) (string, error)

	// Get returns the plaintext for a value returned by Put.
	Get(ctx context.Context, ref, stored string) (string, error)

	// Rewrap returns stored in the ref-bound envelope under the current key.
	// Callers persist the result only during an explicit stop-all migration.
	Rewrap(ctx context.Context, ref, stored string) (rewrapped string, changed bool, err error)

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

// LocalStore implements Store using AES-256-GCM with stable key IDs.
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

func (l *LocalStore) Put(_ context.Context, ref, plaintext string) (string, error) {
	if ref == "" {
		return "", errors.New("secrets: ref is required")
	}
	stored, err := l.enc.EncryptWithAAD(plaintext, ref)
	if err != nil {
		return "", err
	}
	return localEnvelopePrefix + stored, nil
}

func (l *LocalStore) Get(_ context.Context, ref, stored string) (string, error) {
	if strings.HasPrefix(stored, localEnvelopePrefix) {
		if ref == "" {
			return "", errors.New("secrets: ref is required")
		}
		return l.enc.DecryptWithAAD(strings.TrimPrefix(stored, localEnvelopePrefix), ref)
	}
	// Unwrapped compatibility ciphertext carries no authenticated ref.
	return l.enc.Decrypt(stored)
}

func (l *LocalStore) Rewrap(ctx context.Context, ref, stored string) (string, bool, error) {
	if strings.HasPrefix(stored, localEnvelopePrefix) && !l.enc.NeedsRewrap(strings.TrimPrefix(stored, localEnvelopePrefix)) {
		// Authenticate the ref even when no write is needed.
		if _, err := l.Get(ctx, ref, stored); err != nil {
			return "", false, err
		}
		return stored, false, nil
	}
	plaintext, err := l.Get(ctx, ref, stored)
	if err != nil {
		return "", false, err
	}
	rewrapped, err := l.Put(ctx, ref, plaintext)
	return rewrapped, err == nil, err
}

func (l *LocalStore) Seal(_ context.Context, aad, plaintext string) (string, error) {
	return l.enc.EncryptWithAAD(plaintext, aad)
}

func (l *LocalStore) Open(_ context.Context, aad, sealed string) (string, error) {
	return l.enc.DecryptWithAAD(sealed, aad)
}
