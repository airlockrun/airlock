package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// RunMigrations runs all pending database migrations using goose.
func RunMigrations(databaseURL string) error {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return fmt.Errorf("db: open for migrations: %w", err)
	}
	defer db.Close()

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("db: goose dialect: %w", err)
	}
	if err := goose.UpContext(context.Background(), db, "migrations"); err != nil {
		return fmt.Errorf("db: run migrations: %w", err)
	}
	return nil
}

// testLockKey is the advisory lock key shared by all test packages.
const testLockKey = 74656874

// TestLockAndReset acquires a PostgreSQL session-level advisory lock, resets
// the public schema, and runs migrations. The lock is held until release() is
// called. Use this in TestMain to serialize test packages that share a database:
//
//	func TestMain(m *testing.M) {
//	    url := os.Getenv("DATABASE_URL")
//	    if url == "" { os.Exit(m.Run()) }
//	    release, err := db.TestLockAndReset(url)
//	    if err != nil { log.Fatal(err) }
//	    code := m.Run()
//	    release()
//	    os.Exit(code)
//	}
func TestLockAndReset(databaseURL string) (release func(), err error) {
	ctx := context.Background()

	// Use a raw pgx connection (not pooled) so the advisory lock persists
	// for the entire test suite lifetime.
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: connect for test lock: %w", err)
	}

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", testLockKey); err != nil {
		conn.Close(ctx)
		return nil, fmt.Errorf("db: advisory lock: %w", err)
	}

	if _, err := conn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
		conn.Close(ctx)
		return nil, fmt.Errorf("db: reset schema: %w", err)
	}

	if err := RunMigrations(databaseURL); err != nil {
		conn.Close(ctx)
		return nil, err
	}

	return func() { conn.Close(context.Background()) }, nil
}
