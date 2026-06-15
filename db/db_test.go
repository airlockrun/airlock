package db

import (
	"context"
	"os"
	"testing"

	"github.com/airlockrun/airlock/db/dbtest"
)

// testURL is the DSN of the ephemeral database provisioned in TestMain.
// Empty when no database is available.
var testURL string

func TestMain(m *testing.M) {
	url, _, release, ok := dbtest.Setup(context.Background(), RunMigrations)
	if !ok {
		os.Exit(m.Run()) // no DB available; integration tests skip individually
	}
	testURL = url
	code := m.Run()
	release()
	os.Exit(code)
}

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	if testURL == "" {
		t.Skip("no test database (Docker unavailable)")
	}
	return testURL
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
	// Migrations already ran in TestMain. Just verify they're idempotent.
	url := testDatabaseURL(t)
	if err := RunMigrations(url); err != nil {
		t.Fatalf("RunMigrations() failed: %v", err)
	}
}
