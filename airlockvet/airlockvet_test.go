package airlockvet

import (
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestNoDBQ(t *testing.T) {
	dir, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs testdata: %v", err)
	}
	prev := apiPkgPath
	apiPkgPath = "dbqapi"
	t.Cleanup(func() { apiPkgPath = prev })
	analysistest.Run(t, dir, NoDBQ, "dbqapi")
}

func TestWriteProto(t *testing.T) {
	dir, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs testdata: %v", err)
	}
	prev := apiPkgPath
	apiPkgPath = "jsonapi"
	t.Cleanup(func() { apiPkgPath = prev })
	analysistest.Run(t, dir, WriteProto, "jsonapi")
}

func TestNoInlineRole(t *testing.T) {
	dir, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs testdata: %v", err)
	}
	analysistest.Run(t, dir, NoInlineRole, "inlineroleapi")
}

func TestAgentWire(t *testing.T) {
	dir, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatalf("abs testdata: %v", err)
	}
	prev := agentapiPkgPath
	agentapiPkgPath = "agentapi"
	t.Cleanup(func() { agentapiPkgPath = prev })
	analysistest.Run(t, dir, AgentWire, "agentapi")
}
