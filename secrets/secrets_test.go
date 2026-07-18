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

func TestLocalStoreBindsRef(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stored, err := s.Put(ctx, "ref-a", "secret")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, err := s.Get(ctx, "ref-b", stored); err == nil {
		t.Fatal("Get with different ref succeeded")
	}
}

func TestLocalStoreRejectsMissingEnvelope(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Get(context.Background(), "ref-a", "airlock-crypto:v2:key:ciphertext"); err == nil {
		t.Fatal("Get accepted a secret without the Store envelope")
	}
	if _, _, err := s.Rewrap(context.Background(), "ref-a", "airlock-crypto:v2:key:ciphertext"); err == nil {
		t.Fatal("Rewrap accepted a secret without the Store envelope")
	}
}

func TestLocalStoreRewrapsEnvelopeToCurrentKey(t *testing.T) {
	oldKey := make([]byte, 32)
	newKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i], newKey[i] = 1, 2
	}
	oldStore := NewLocal(crypto.New(oldKey))
	stored, err := oldStore.Put(context.Background(), "ref-a", "secret")
	if err != nil {
		t.Fatal(err)
	}
	rotatingStore := NewLocal(crypto.New(newKey, oldKey))
	got, changed, err := rotatingStore.Rewrap(context.Background(), "ref-a", stored)
	if err != nil || !changed || got == stored {
		t.Fatalf("rotation Rewrap = (%q, %v, %v), want changed", got, changed, err)
	}
}

func TestLocalStoreRejectsPlaintext(t *testing.T) {
	if _, err := newTestStore(t).Get(context.Background(), "ref-a", "plain-secret"); err == nil {
		t.Fatal("Get accepted plaintext")
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
