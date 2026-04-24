package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgxpool.Pool.
type DB struct {
	pool *pgxpool.Pool
}

// New creates a new DB, connecting to the given database URL.
func New(ctx context.Context, databaseURL string) *DB {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		panic(fmt.Sprintf("db: failed to connect: %v", err))
	}
	if err := pool.Ping(ctx); err != nil {
		panic(fmt.Sprintf("db: failed to ping: %v", err))
	}

	return &DB{pool: pool}
}

// Close closes the connection pool.
func (d *DB) Close() {
	d.pool.Close()
}

// Pool returns the underlying pool.
func (d *DB) Pool() *pgxpool.Pool {
	return d.pool
}
