package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// broadcastSiblingChange triggers a /refresh on every active agent
// except the one whose change caused the broadcast.
//
// Without this, a freshly-created agent doesn't appear as a sibling on
// other agents until they restart — the agentsdk syncs only at process
// start and on explicit /refresh, and the only existing /refresh caller
// is the OAuth credential-completed handler. With A2A bindings now
// actually executable from run_js, that staleness becomes user-visible
// ("agent_foo is not defined"). The fan-out happens in its own
// goroutine so the user-facing handler (CreateAgent/Sync/DeleteAgent)
// returns immediately; failures are logged, not surfaced.
//
// RefreshAgent itself is a no-op for cold containers — they'll pick up
// the change on their next startup sync, which is the correct behaviour.
// Best-effort by design.
func broadcastSiblingChange(ctx context.Context, q *dbq.Queries, dispatcher *trigger.Dispatcher, logger *zap.Logger, changedAgentID uuid.UUID) {
	if dispatcher == nil {
		return
	}
	rows, err := q.ListActiveAgentIDs(ctx)
	if err != nil {
		logger.Error("broadcast: list active agents", zap.Error(err))
		return
	}
	var wg sync.WaitGroup
	for _, r := range rows {
		id := uuid.UUID(r.Bytes)
		if id == changedAgentID {
			continue
		}
		wg.Add(1)
		go func(target uuid.UUID) {
			defer wg.Done()
			// Detached context: the caller's request might be cancelled
			// before we finish, but the refresh should still run.
			rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := dispatcher.RefreshAgent(rctx, target); err != nil {
				logger.Warn("broadcast: refresh failed",
					zap.String("agent_id", target.String()),
					zap.Error(err))
			}
		}(id)
	}
	wg.Wait()
}

// bytesEqual is the obvious byte-slice equality. Stays here rather than
// reaching for bytes.Equal to keep agent_broadcast.go self-contained.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// computeToolsHash produces a stable hash over the (name, input_schema,
// output_schema, access) tuples of an agent's registered tools. The
// sync handler stores this in agents.tools_hash and compares before/
// after to decide whether to broadcast a sibling-update refresh —
// avoiding redundant fan-out when an agent re-syncs unchanged state on
// container restart.
func computeToolsHash(tools []dbq.AgentTool) []byte {
	type entry struct {
		Name string `json:"n"`
		In   []byte `json:"i"`
		Out  []byte `json:"o"`
		Acc  string `json:"a"`
	}
	sorted := make([]entry, 0, len(tools))
	for _, t := range tools {
		sorted = append(sorted, entry{
			Name: t.Name,
			In:   t.InputSchema,
			Out:  t.OutputSchema,
			Acc:  t.Access,
		})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	buf, _ := json.Marshal(sorted)
	sum := sha256.Sum256(buf)
	return sum[:]
}
