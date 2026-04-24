package api

import (
	"sync"
	"time"
)

const (
	convMutexSweepInterval = time.Minute
	convMutexIdleTimeout   = 5 * time.Minute
)

// convMutexMap provides per-conversation mutexes to serialize prompt processing.
// Only one prompt per conversation is processed at a time — the second blocks
// until the first completes. Different conversations proceed in parallel.
type convMutexMap struct {
	mu    sync.Mutex
	locks map[string]*convMutex
	stop  chan struct{}
}

type convMutex struct {
	mu       sync.Mutex
	refCount int
	lastUsed time.Time
}

// newConvMutexMap creates a convMutexMap and starts its background cleanup goroutine.
func newConvMutexMap() *convMutexMap {
	m := &convMutexMap{
		locks: make(map[string]*convMutex),
		stop:  make(chan struct{}),
	}
	go m.sweepLoop()
	return m
}

// Lock acquires the per-conversation mutex. Blocks if another prompt for the
// same conversation is in progress.
func (m *convMutexMap) Lock(convID string) {
	m.mu.Lock()
	cm, ok := m.locks[convID]
	if !ok {
		cm = &convMutex{}
		m.locks[convID] = cm
	}
	cm.refCount++
	m.mu.Unlock()

	cm.mu.Lock()
}

// Unlock releases the per-conversation mutex.
func (m *convMutexMap) Unlock(convID string) {
	m.mu.Lock()
	cm, ok := m.locks[convID]
	if !ok {
		m.mu.Unlock()
		return
	}
	cm.refCount--
	cm.lastUsed = time.Now()
	m.mu.Unlock()

	cm.mu.Unlock()
}

// Close stops the background sweep goroutine.
func (m *convMutexMap) Close() {
	close(m.stop)
}

// sweepLoop periodically removes idle mutex entries to prevent memory leaks.
func (m *convMutexMap) sweepLoop() {
	ticker := time.NewTicker(convMutexSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.sweep()
		case <-m.stop:
			return
		}
	}
}

func (m *convMutexMap) sweep() {
	cutoff := time.Now().Add(-convMutexIdleTimeout)
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, cm := range m.locks {
		if cm.refCount == 0 && cm.lastUsed.Before(cutoff) {
			delete(m.locks, id)
		}
	}
}
