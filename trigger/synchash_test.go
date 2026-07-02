package trigger

import (
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

func TestAgentConfigHash(t *testing.T) {
	prov := toPgUUID(uuid.New())
	base := dbq.Agent{
		Slug:           "acme",
		ExecProviderID: prov,
		ExecModel:      "gpt-5",
		VisionModel:    "gpt-5",
	}

	// Deterministic: same row → same hash.
	if got, want := AgentConfigHash(base), AgentConfigHash(base); got != want {
		t.Fatalf("hash not deterministic: %s != %s", got, want)
	}

	// Sensitive to each config input the agent renders from.
	changed := []struct {
		name  string
		mutID func(a *dbq.Agent)
	}{
		{"slug", func(a *dbq.Agent) { a.Slug = "other" }},
		{"exec model", func(a *dbq.Agent) { a.ExecModel = "gpt-5-mini" }},
		{"exec provider", func(a *dbq.Agent) { a.ExecProviderID = toPgUUID(uuid.New()) }},
		{"vision model", func(a *dbq.Agent) { a.VisionModel = "" }},
		{"embedding model", func(a *dbq.Agent) { a.EmbeddingModel = "text-embedding-3" }},
	}
	for _, c := range changed {
		mutated := base
		c.mutID(&mutated)
		if AgentConfigHash(mutated) == AgentConfigHash(base) {
			t.Errorf("%s change did not alter the hash", c.name)
		}
	}
}
