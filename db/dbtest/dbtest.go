// Package dbtest provisions a database for integration tests.
//
// It is imported only from _test.go files, so testcontainers-go (and the
// Docker client it drags in) never ends up in the production airlock
// binary. It deliberately does NOT import airlock/db: the migrate behaviour
// is injected by the caller, which keeps this package free of any import
// cycle with the package under test.
//
// Setup starts a throwaway pgvector/pgvector:pg17 container (the exact prod
// image), migrates it, and snapshots the migrated state as a template. The
// returned reset restores that template (DROP + CREATE DATABASE ... WITH
// TEMPLATE) so every test starts from the exact post-migration state —
// including migration-seeded singleton rows like system_settings — without
// re-running migrations. When Docker is unreachable, ok is false and DB
// tests skip.
package dbtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// postgresImage is the prod image so test schema behaviour matches
// production exactly (pgvector extension available, same PG major).
const postgresImage = "pgvector/pgvector:pg17"

// Setup provisions a migrated database for the calling test package.
//
//   - dsn: the connection string tests should use.
//   - reset: restores the post-migration snapshot. Because reset drops and
//     recreates the database, the caller MUST close and rebuild its
//     connection pool around each reset call.
//   - release: torn down from TestMain after m.Run().
//   - ok: false when no database could be provisioned (no Docker); callers
//     should still run non-DB tests and let DB tests skip.
//
// Pass db.RunMigrations as migrate.
func Setup(
	ctx context.Context,
	migrate func(dsn string) error,
) (dsn string, reset func() error, release func(), ok bool) {
	// Isolate the migrations' filesystem side effects into a throwaway
	// dir. Migration 003 rewrites per-agent git repos under
	// AGENT_REPOS_PATH; pointed at an empty tree it no-ops, so the
	// schema-provisioning run can't race parallel test packages on the
	// shared host path (separate testcontainer DBs, one filesystem) or
	// mutate the real /var/lib/airlock agent repos. Each test process
	// gets its own dir.
	agentsDir, err := os.MkdirTemp("", "airlock-dbtest-agents-*")
	if err != nil {
		panic(fmt.Sprintf("dbtest: temp agents dir: %v", err))
	}
	os.Setenv("AGENT_REPOS_PATH", agentsDir)
	os.Setenv("AGENT_MONOREPO_PATH", filepath.Join(agentsDir, "monorepo"))
	cleanupAgents := func() { _ = os.RemoveAll(agentsDir) }

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
		cleanupAgents()
		return "", nil, func() {}, false
	}

	terminate := func() {
		_ = ctr.Terminate(context.Background())
		cleanupAgents()
	}

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
