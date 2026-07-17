package api

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

func TestHealthProbeCacheCoalescesAndCaches(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	cache := healthProbeCache{
		ttl: time.Minute,
		probe: func() healthProbeResult {
			calls.Add(1)
			<-release
			return healthProbeResult{dbOK: true, s3OK: true}
		},
	}

	const requests = 20
	var wg sync.WaitGroup
	wg.Add(requests)
	for range requests {
		go func() {
			defer wg.Done()
			if got := cache.get(); !got.dbOK || !got.s3OK {
				t.Errorf("cache.get() = %+v", got)
			}
		}()
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
	cache.get()
	if got := calls.Load(); got != 1 {
		t.Fatalf("cached probe calls = %d, want 1", got)
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
