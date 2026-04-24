package db

import (
	"context"
	"log"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		os.Exit(m.Run()) // skip DB tests, they'll call t.Skip individually
	}
	release, err := TestLockAndReset(url)
	if err != nil {
		log.Fatal(err)
	}
	code := m.Run()
	release()
	os.Exit(code)
}

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}
	return url
}

func TestDBConnectAndPing(t *testing.T) {
	url := testDatabaseURL(t)
	ctx := context.Background()

	db := New(ctx, url)
	defer db.Close()

	err := db.Pool().Ping(ctx)
	if err != nil {
		t.Fatalf("ping failed: %v", err)
	}
}

func TestRunMigrations(t *testing.T) {
	// Migrations already ran in TestMain via TestLockAndReset.
	// Just verify we can run them again (idempotent).
	url := testDatabaseURL(t)
	if err := RunMigrations(url); err != nil {
		t.Fatalf("RunMigrations() failed: %v", err)
	}
}

