package sysagent

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/llmledger"
	"github.com/airlockrun/goai/stream"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// recordSystemRunUsage writes this turn's accumulated model spend to the
// shared llm_usage ledger and refreshes the system run's cost aggregate.
//
// The sysagent runs the model loop in-process, so there is one accumulated
// stream.Usage per turn (not one per round-trip like the runtime proxy) —
// recorded as a single ledger row attributed to the operator (UserID) and
// this system run (SystemRunID), call_kind "system". agent_id is left null:
// the system agent has no agent row. Cost is computed from the same
// sol/provider catalog every other ledger writer uses.
//
// Best-effort: accounting must never break a turn that already ran. Uses a
// fresh bounded ctx so a cancelled turn still records the tokens it burned.
func (s *Service) recordSystemRunUsage(runID, userID uuid.UUID, providerCatalogID, model string, usage stream.Usage, errored bool) {
	c := llmledger.Capture{
		SystemRunID:       pgtype.UUID{Bytes: runID, Valid: true},
		UserID:            pgtype.UUID{Bytes: userID, Valid: true},
		ProviderCatalogID: providerCatalogID,
		ProviderSlug:      providerCatalogID,
		Model:             model,
		Capability:        "text",
		CallKind:          "system",
		Slug:              "sysagent",
		Errored:           errored,
	}
	c.TokensFromStreamUsage(usage)
	if c.TokensIn == 0 && c.TokensOut == 0 {
		return // no model call happened (e.g. an error before the first round-trip)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q := dbq.New(s.db.Pool())
	llmledger.Record(ctx, q, s.logger, c)
	if err := q.UpdateSystemRunLLMStats(ctx, pgtype.UUID{Bytes: runID, Valid: true}); err != nil {
		s.logger.Error("sysagent: aggregate system run llm stats", zap.Error(err))
	}
}
