package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"

	// Blank import so each migration .go file's init() runs at startup
	// and registers itself with goose before RunMigrations calls UpContext.
	// SQL migrations are picked up by the embed.FS below; Go migrations
	// have to be code-resident, which means they need to be in a package
	// somebody imports.
	_ "github.com/airlockrun/airlock/db/migrations"
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
