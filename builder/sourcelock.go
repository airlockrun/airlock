package builder

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SourceLock serializes source-tree mutations for one agent across replicas.
type SourceLock struct {
	conn *pgxpool.Conn
	key  string
}

// AcquireSourceLock obtains a session advisory lock keyed by the stable agent
// UUID. Call Unlock exactly once.
func (b *BuildService) AcquireSourceLock(ctx context.Context, agentID string) (*SourceLock, error) {
	conn, err := b.db.Pool().Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire source lock connection: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, agentID); err != nil {
		conn.Release()
		return nil, fmt.Errorf("acquire source lock: %w", err)
	}
	return &SourceLock{conn: conn, key: agentID}, nil
}

// Unlock releases the advisory lock and its dedicated pool connection.
func (l *SourceLock) Unlock() {
	if l == nil || l.conn == nil {
		panic("builder: SourceLock.Unlock called on nil lock")
	}
	_, _ = l.conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, l.key)
	l.conn.Release()
	l.conn = nil
}
