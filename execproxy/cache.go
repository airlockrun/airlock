package execproxy

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// clientCache holds *ssh.Client connections keyed by endpoint UUID so
// repeated exec calls against the same target reuse the TCP+SSH
// handshake (~150–250ms saved per call). Entries are evicted on idle
// or on explicit Evict() — operators expect a keypair rotation or host
// change to take effect immediately.
//
// Multi-replica caveat: the cache is per-process. Eviction is local. A
// rotation on replica A leaves replica B with the old cached client
// until its idle timer fires. Acceptable for single-instance today;
// when multi-replica lands, swap to LISTEN/NOTIFY-driven cross-process
// invalidation.
type clientCache struct {
	mu      sync.Mutex
	entries map[uuid.UUID]*cacheEntry
	idle    time.Duration
}

type cacheEntry struct {
	client     *ssh.Client
	lastUsedAt time.Time
}

func newClientCache(idle time.Duration) *clientCache {
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	return &clientCache{
		entries: make(map[uuid.UUID]*cacheEntry),
		idle:    idle,
	}
}

// Get returns the cached client for id or nil if absent / expired. The
// caller is expected to dial a fresh client on nil, then store via Put.
func (c *clientCache) Get(id uuid.UUID) *ssh.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok {
		return nil
	}
	if time.Since(e.lastUsedAt) > c.idle {
		_ = e.client.Close()
		delete(c.entries, id)
		return nil
	}
	e.lastUsedAt = time.Now()
	return e.client
}

// Put stores client under id. If a previous entry existed under id,
// the old client is closed.
func (c *clientCache) Put(id uuid.UUID, client *ssh.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[id]; ok {
		_ = e.client.Close()
	}
	c.entries[id] = &cacheEntry{client: client, lastUsedAt: time.Now()}
}

// Evict closes and removes the entry for id. Called synchronously when
// the operator changes transport config, rotates the keypair, or clears
// the host key — anything that would otherwise leave the cache holding
// a connection bound to stale credentials.
func (c *clientCache) Evict(id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[id]; ok {
		_ = e.client.Close()
		delete(c.entries, id)
	}
}

// reapLoop closes idle entries on a fixed cadence. Runs for the lifetime
// of the SSHDialer; cancel via ctx.
func (c *clientCache) reapLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(c.idle / 2)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.reapOnce()
		}
	}
}

func (c *clientCache) reapOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for id, e := range c.entries {
		if now.Sub(e.lastUsedAt) > c.idle {
			_ = e.client.Close()
			delete(c.entries, id)
		}
	}
}
