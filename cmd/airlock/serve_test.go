package main

import (
	"context"
	"testing"
)

func TestRewrapStoredSecretsDisabledDoesNotAccessDatabase(t *testing.T) {
	changed, err := rewrapStoredSecrets(context.Background(), nil, nil, false)
	if err != nil || changed != 0 {
		t.Fatalf("rewrapStoredSecrets disabled = %d, %v", changed, err)
	}
}
