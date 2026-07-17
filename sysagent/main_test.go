package sysagent

import (
	"context"
	"os"
	"testing"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbtest"
)

var sysagentTestDB *db.DB

func TestMain(m *testing.M) {
	url, _, release, ok := dbtest.Setup(context.Background(), db.RunMigrations)
	if !ok {
		os.Exit(m.Run())
	}
	sysagentTestDB = db.New(context.Background(), url)
	code := m.Run()
	sysagentTestDB.Close()
	release()
	os.Exit(code)
}

func requireSysagentTestDB(t *testing.T) {
	t.Helper()
	if sysagentTestDB == nil {
		t.Skip("no test database (Docker unavailable)")
	}
}
