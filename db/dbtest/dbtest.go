// Package dbtest provisions a database for integration tests.
//
// It is imported only from _test.go files, so testcontainers-go (and the
// Docker client it drags in) never ends up in the production airlock
// binary. It deliberately does NOT import airlock/db: the migrate/reset
// behaviour is injected by the caller, which keeps this package free of
// any import cycle with the package under test.
//
// By default Setup starts a throwaway pgvector/pgvector:pg17 container
// (the exact prod image), migrates it, and snapshots the migrated state
// as a template. The returned Reset restores that template (DROP +
// CREATE DATABASE ... WITH TEMPLATE) so every test starts from the exact
// post-migration state — including migration-seeded singleton rows like
// system_settings — without re-running migrations.
//
// Setup NEVER reads DATABASE_URL — that variable points at the real dev
// database in docker-compose and keying tests off it is what used to
// wipe dev data. To run against an externally-managed, disposable
// Postgres (e.g. a CI service), set TEST_DATABASE_URL; that database is
// advisory-locked and schema-reset once. The external path does NOT get
// per-test Reset (Reset is nil) — it's an opt-in escape hatch and such
// tests must clean up after themselves.
package dbtest

import (
	"context"
	"fmt"
	"os"

	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// postgresImage is the prod image so test schema behaviour matches
// production exactly (pgvector extension available, same PG major).
const postgresImage = "pgvector/pgvector:pg17"

// Setup provisions a migrated database for the calling test package.
//
//   - dsn: the connection string tests should use.
//   - reset: restores the post-migration snapshot; nil for the external
//     TEST_DATABASE_URL path. Because Reset drops and recreates the
//     database, the caller MUST close and rebuild its connection pool
//     around each reset call.
//   - release: torn down from TestMain after m.Run().
//   - ok: false when no database could be provisioned (no Docker and no
//     TEST_DATABASE_URL); callers should still run non-DB tests and let
//     DB tests skip.
//
// migrate runs the schema on an exclusive container DSN. lockReset
// prepares an externally-provided shared DSN (advisory lock + schema
// reset + migrate) and returns its own release. Pass db.RunMigrations
// and db.TestLockAndReset respectively.
func Setup(
	ctx context.Context,
	migrate func(dsn string) error,
	lockReset func(dsn string) (func(), error),
) (dsn string, reset func() error, release func(), ok bool) {
	if ext := os.Getenv("TEST_DATABASE_URL"); ext != "" {
		rel, err := lockReset(ext)
		if err != nil {
			panic(fmt.Sprintf("dbtest: TEST_DATABASE_URL setup: %v", err))
		}
		return ext, nil, rel, true
	}

	ctr, err := postgres.Run(ctx, postgresImage,
		postgres.WithDatabase("airlock_test"),
		postgres.WithUsername("airlock"),
		postgres.WithPassword("airlock"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		// Most commonly: no Docker daemon reachable. Skip DB tests
		// rather than hard-fail the whole suite.
		if ctr != nil {
			_ = ctr.Terminate(context.Background())
		}
		return "", nil, func() {}, false
	}

	terminate := func() { _ = ctr.Terminate(context.Background()) }

	d, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		terminate()
		panic(fmt.Sprintf("dbtest: connection string: %v", err))
	}
	if err := migrate(d); err != nil {
		terminate()
		panic(fmt.Sprintf("dbtest: migrations: %v", err))
	}
	// Snapshot AFTER migrate and BEFORE the caller opens its pool:
	// CREATE DATABASE ... WITH TEMPLATE requires no connections to the
	// source database, and migrate() closes its own connections.
	if err := ctr.Snapshot(ctx); err != nil {
		terminate()
		panic(fmt.Sprintf("dbtest: snapshot: %v", err))
	}
	return d, func() error { return ctr.Restore(ctx) }, terminate, true
}
