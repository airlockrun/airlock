package api

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProbeHealthUsesIndependentTimeouts(t *testing.T) {
	dbPing := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	s3Ping := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	}

	dbOK, s3OK := probeHealth(context.Background(), time.Millisecond, dbPing, s3Ping)
	if dbOK {
		t.Error("dbOK = true, want false")
	}
	if !s3OK {
		t.Error("s3OK = false, want true")
	}
}

func TestProbeHealthHonorsRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ping := func(ctx context.Context) error {
		return ctx.Err()
	}

	dbOK, s3OK := probeHealth(ctx, time.Second, ping, ping)
	if dbOK || s3OK {
		t.Errorf("probeHealth() = (%v, %v), want (false, false)", dbOK, s3OK)
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("context error = %v, want context.Canceled", ctx.Err())
	}
}
