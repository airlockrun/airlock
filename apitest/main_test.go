package apitest_test

import (
	"os"
	"testing"

	"github.com/airlockrun/airlock/apitest"
)

func TestMain(m *testing.M) {
	os.Exit(apitest.PackageMain(m))
}
