package builder

import (
	"context"
	"errors"
	"testing"
)

func TestExecuteWaitsForBuildCapacityBeforeDependencies(t *testing.T) {
	b := &BuildService{buildSem: make(chan struct{}, 1)}
	b.buildSem <- struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := b.Execute(ctx, BuildPlan{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute() error = %v, want context.Canceled", err)
	}
}
