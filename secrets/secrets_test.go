package secrets

import (
	"context"
	"testing"

	"github.com/airlockrun/airlock/crypto"
)

func newTestStore(t *testing.T) *LocalStore {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return NewLocal(crypto.New(key))
}

func TestLocalStoreRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stored, err := s.Put(ctx, "connection/abc/access_token", "sk-live-xyz")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if stored == "" {
		t.Fatal("Put returned empty string")
	}

	plain, err := s.Get(ctx, "connection/abc/access_token", stored)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if plain != "sk-live-xyz" {
		t.Fatalf("plaintext mismatch: got %q", plain)
	}
}

func TestLocalStoreRefIgnored(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stored, err := s.Put(ctx, "ref-a", "secret")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// LocalStore decrypts regardless of ref — the ciphertext is self-contained.
	plain, err := s.Get(ctx, "ref-b", stored)
	if err != nil {
		t.Fatalf("Get with different ref: %v", err)
	}
	if plain != "secret" {
		t.Fatalf("plaintext mismatch: got %q", plain)
	}
}

func TestNewLocalNilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil encryptor")
		}
	}()
	NewLocal(nil)
}
