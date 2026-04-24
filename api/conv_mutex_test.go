package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConvMutexMap(t *testing.T) {
	t.Run("serial same conversation", func(t *testing.T) {
		m := newConvMutexMap()
		defer m.Close()

		var seq atomic.Int32
		var wg sync.WaitGroup
		wg.Add(2)

		// First goroutine acquires lock and holds it briefly.
		go func() {
			defer wg.Done()
			m.Lock("c1")
			seq.Add(1) // seq = 1
			time.Sleep(50 * time.Millisecond)
			m.Unlock("c1")
		}()

		// Give the first goroutine time to acquire.
		time.Sleep(10 * time.Millisecond)

		// Second goroutine blocks until first releases.
		go func() {
			defer wg.Done()
			m.Lock("c1")
			got := seq.Load()
			if got != 1 {
				t.Errorf("second goroutine ran before first completed: seq=%d", got)
			}
			seq.Add(1) // seq = 2
			m.Unlock("c1")
		}()

		wg.Wait()
		if seq.Load() != 2 {
			t.Fatalf("expected seq=2, got %d", seq.Load())
		}
	})

	t.Run("parallel different conversations", func(t *testing.T) {
		m := newConvMutexMap()
		defer m.Close()

		// Both goroutines should start concurrently.
		var started atomic.Int32
		gate := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		for _, convID := range []string{"c1", "c2"} {
			go func(id string) {
				defer wg.Done()
				m.Lock(id)
				started.Add(1)
				<-gate // wait until both have started
				m.Unlock(id)
			}(convID)
		}

		// Wait for both to acquire their locks.
		deadline := time.After(time.Second)
		for started.Load() < 2 {
			select {
			case <-deadline:
				t.Fatal("timed out waiting for both goroutines to start")
			default:
				time.Sleep(time.Millisecond)
			}
		}
		close(gate)
		wg.Wait()
	})

	t.Run("cleanup on idle", func(t *testing.T) {
		m := newConvMutexMap()
		defer m.Close()

		m.Lock("c1")
		m.Unlock("c1")

		// Backdate lastUsed so sweep will clean it up.
		m.mu.Lock()
		m.locks["c1"].lastUsed = time.Now().Add(-10 * time.Minute)
		m.mu.Unlock()

		m.sweep()

		m.mu.Lock()
		_, exists := m.locks["c1"]
		m.mu.Unlock()
		if exists {
			t.Fatal("expected c1 to be swept")
		}
	})

	t.Run("no cleanup while in use", func(t *testing.T) {
		m := newConvMutexMap()
		defer m.Close()

		m.Lock("c1")

		// Backdate — but refCount > 0, so it should survive.
		m.mu.Lock()
		m.locks["c1"].lastUsed = time.Now().Add(-10 * time.Minute)
		m.mu.Unlock()

		m.sweep()

		m.mu.Lock()
		_, exists := m.locks["c1"]
		m.mu.Unlock()
		if !exists {
			t.Fatal("expected c1 to survive sweep while in use")
		}

		m.Unlock("c1")
	})
}
