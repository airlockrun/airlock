package trigger

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

// AgentConfigHash fingerprints the subset of an agent's configuration that is a
// pure function of the agents row and feeds the sync-time PromptData the agent
// caches: the eight model slots (which drive Capabilities + SupportedModalities)
// and the slug (which drives the dashboard/route URLs). Airlock stamps this on
// every dispatched PromptInput.ExpectedSyncHash and returns it as
// SyncResponse.SyncStateHash; the agent compares the two and resyncs on drift,
// so a model or slug change self-heals even if it didn't fire an explicit
// /refresh. Computed on the fly from the row rather than stored, so the
// fingerprint itself can never go stale.
//
// Relational prompt inputs — the sibling roster and MCP schemas — are NOT
// covered here: they aren't a function of the agents row, and they already have
// their own event-driven refresh broadcast.
func AgentConfigHash(ag dbq.Agent) string {
	slots := []struct {
		provider pgtype.UUID
		model    string
	}{
		{ag.BuildProviderID, ag.BuildModel},
		{ag.ExecProviderID, ag.ExecModel},
		{ag.SttProviderID, ag.SttModel},
		{ag.VisionProviderID, ag.VisionModel},
		{ag.TtsProviderID, ag.TtsModel},
		{ag.ImageGenProviderID, ag.ImageGenModel},
		{ag.EmbeddingProviderID, ag.EmbeddingModel},
		{ag.SearchProviderID, ag.SearchModel},
	}
	var b strings.Builder
	b.WriteString(ag.Slug)
	for _, s := range slots {
		b.WriteByte('|')
		if s.provider.Valid {
			b.WriteString(hex.EncodeToString(s.provider.Bytes[:]))
		}
		b.WriteByte(':')
		b.WriteString(s.model)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
