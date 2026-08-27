package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AdvisoryLock holds one session-level PostgreSQL advisory lock on a dedicated
// pool connection. Unlock must be called exactly once.
type AdvisoryLock struct {
	conn *pgx.Conn
	key  string
}

// AcquireAdvisoryLock serializes cross-replica work identified by key without
// holding row locks needed by callbacks performed during that work.
func (d *DB) AcquireAdvisoryLock(ctx context.Context, key string) (*AdvisoryLock, error) {
	for {
		conn, err := pgx.Connect(ctx, d.databaseURL)
		if err != nil {
			return nil, fmt.Errorf("connect advisory lock session: %w", err)
		}
		var acquired bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key).Scan(&acquired); err != nil {
			_ = conn.Close(context.Background())
			return nil, fmt.Errorf("try advisory lock: %w", err)
		}
		if acquired {
			return &AdvisoryLock{conn: conn, key: key}, nil
		}
		_ = conn.Close(context.Background())
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// TryAcquireAdvisoryLock obtains the lock without waiting.
func (d *DB) TryAcquireAdvisoryLock(ctx context.Context, key string) (*AdvisoryLock, bool, error) {
	conn, err := pgx.Connect(ctx, d.databaseURL)
	if err != nil {
		return nil, false, fmt.Errorf("connect advisory lock session: %w", err)
	}
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key).Scan(&acquired); err != nil {
		_ = conn.Close(context.Background())
		return nil, false, fmt.Errorf("try advisory lock: %w", err)
	}
	if !acquired {
		_ = conn.Close(context.Background())
		return nil, false, nil
	}
	return &AdvisoryLock{conn: conn, key: key}, true, nil
}

// Unlock releases the advisory lock and its dedicated connection.
func (l *AdvisoryLock) Unlock() {
	if l == nil || l.conn == nil {
		panic("db: AdvisoryLock.Unlock called on nil lock")
	}
	_, _ = l.conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, l.key)
	_ = l.conn.Close(context.Background())
	l.conn = nil
}
