package trigger

import (
	"context"
	"os"
	"testing"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbtest"
)

var (
	triggerTestDB    *db.DB
	triggerTestURL   string
	triggerTestReset func() error
)

func TestMain(m *testing.M) {
	url, reset, release, ok := dbtest.Setup(context.Background(), db.RunMigrations)
	if !ok {
		os.Exit(m.Run())
	}
	triggerTestURL, triggerTestReset = url, reset
	triggerTestDB = db.New(context.Background(), url)
	code := m.Run()
	triggerTestDB.Close()
	release()
	os.Exit(code)
}

func skipIfNoTriggerDB(t *testing.T) {
	t.Helper()
	if triggerTestDB == nil {
		t.Skip("no test database (Docker unavailable)")
	}
	triggerTestDB.Close()
	if err := triggerTestReset(); err != nil {
		t.Fatalf("restore test database: %v", err)
	}
	triggerTestDB = db.New(context.Background(), triggerTestURL)
}
