package builder

import (
	"context"
	"fmt"

	airlockdb "github.com/airlockrun/airlock/db"
)

// SourceLock serializes source-tree mutations for one agent across replicas.
type SourceLock struct {
	lock *airlockdb.AdvisoryLock
}

// AcquireSourceLock obtains a session advisory lock keyed by the stable agent
// UUID. Call Unlock exactly once.
func (b *BuildService) AcquireSourceLock(ctx context.Context, agentID string) (*SourceLock, error) {
	lock, err := b.db.AcquireAdvisoryLock(ctx, "agent-source:"+agentID)
	if err != nil {
		return nil, fmt.Errorf("acquire source lock: %w", err)
	}
	return &SourceLock{lock: lock}, nil
}

// TryAcquireSourceLock obtains the source lock only when no other replica holds
// it. A busy lock returns (nil, false, nil) without waiting.
func (b *BuildService) TryAcquireSourceLock(ctx context.Context, agentID string) (*SourceLock, bool, error) {
	lock, acquired, err := b.db.TryAcquireAdvisoryLock(ctx, "agent-source:"+agentID)
	if err != nil {
		return nil, false, fmt.Errorf("try source lock: %w", err)
	}
	if !acquired {
		return nil, false, nil
	}
	return &SourceLock{lock: lock}, true, nil
}

// Unlock releases the advisory lock and its dedicated pool connection.
func (l *SourceLock) Unlock() {
	if l == nil || l.lock == nil {
		panic("builder: SourceLock.Unlock called on nil lock")
	}
	l.lock.Unlock()
	l.lock = nil
}
