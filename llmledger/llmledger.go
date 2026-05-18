// Package llmledger is the single writer for the llm_usage ledger — the
// authoritative record of every LLM token/cost charge in Airlock. Both
// the runtime model proxy (api) and the in-process build codegen runner
// (builder) funnel through Record so cost computation lives in exactly
// one place. Runtime calls attribute to a run (RunID); build/upgrade
// codegen attributes to a build (BuildID); CallKind disambiguates.
package llmledger

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/goai/stream"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// warnOnceSeen dedups operator-misconfiguration warnings (model missing
// from the catalog, or an image/audio model with no unit rate) so a busy
// installation doesn't spam the log. Keyed by a stable per-condition
// string; first occurrence logs, the rest stay silent for the process
// lifetime.
var warnOnceSeen sync.Map

func warnOnce(logger *zap.Logger, key, msg string, fields ...zap.Field) {
	if _, loaded := warnOnceSeen.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	logger.Warn(msg, fields...)
}

// Capture is one fully-resolved model charge. Attribution (RunID/BuildID/
// UserID/ConversationID) is the caller's responsibility — the api side
// resolves it from the run row, the builder side sets BuildID directly.
// Exactly one of RunID/BuildID is normally Valid (or neither, for an
// unattributed call); they are not mutually enforced here.
type Capture struct {
	AgentID        pgtype.UUID
	RunID          pgtype.UUID
	BuildID        pgtype.UUID
	UserID         pgtype.UUID
	ConversationID pgtype.UUID

	ProviderCatalogID string
	Model             string
	Capability        string
	CallKind          string
	Slug              string

	TokensIn        int64
	TokensOut       int64
	TokensCached    int64
	TokensReasoning int64

	Units    float64
	UnitKind string // "" | "image" | "character" | "second"

	FinishReason string
	Errored      bool
	Latency      time.Duration
}

// TokensFromStreamUsage populates the token fields from an accumulated
// stream.Usage — totals plus the cache-read / reasoning breakdown when
// the provider reported it. Shared by every caller that has a
// stream.Usage in hand (the build codegen runner; the runtime proxy uses
// its own accumulator before handing tokens over).
func (c *Capture) TokensFromStreamUsage(u stream.Usage) {
	c.TokensIn = int64(u.InputTotal())
	c.TokensOut = int64(u.OutputTotal())
	if u.InputTokens.CacheRead != nil {
		c.TokensCached = int64(*u.InputTokens.CacheRead)
	}
	if u.OutputTokens.Reasoning != nil {
		c.TokensReasoning = int64(*u.OutputTokens.Reasoning)
	}
}

// Record computes cost and writes one append-only llm_usage row.
// Best-effort: every failure is logged and swallowed — accounting must
// never break a model call (runtime or build) that already happened.
// Callers pass their own ctx; use a fresh bounded one if the request
// context may already be cancelled (e.g. client disconnected mid-stream).
func Record(ctx context.Context, q *dbq.Queries, logger *zap.Logger, c Capture) {
	costIn, costOut := cost(ctx, q, logger, c)

	if err := q.InsertLLMUsage(ctx, dbq.InsertLLMUsageParams{
		AgentID:           c.AgentID,
		RunID:             c.RunID,
		BuildID:           c.BuildID,
		UserID:            c.UserID,
		ConversationID:    c.ConversationID,
		ProviderCatalogID: c.ProviderCatalogID,
		Model:             c.Model,
		Capability:        c.Capability,
		CallKind:          c.CallKind,
		Slug:              c.Slug,
		TokensIn:          c.TokensIn,
		TokensOut:         c.TokensOut,
		TokensCached:      c.TokensCached,
		TokensReasoning:   c.TokensReasoning,
		Units:             c.Units,
		UnitKind:          c.UnitKind,
		CostInput:         costIn,
		CostOutput:        costOut,
		CostTotal:         costIn + costOut,
		FinishReason:      c.FinishReason,
		Errored:           c.Errored,
		LatencyMs:         int32(c.Latency.Milliseconds()),
	}); err != nil {
		logger.Error("llm usage: insert failed", zap.Error(err))
	}
}

// cost returns (cost_input, cost_output) in dollars. Token-priced models
// use the sol/provider (models.dev) catalog. Image/audio calls the
// catalog can't price fall back to the operator-set llm_unit_rates table;
// a missing rate yields 0 (visible, never fabricated). Unit-priced cost
// lands entirely in cost_input (cost_output 0).
func cost(ctx context.Context, q *dbq.Queries, logger *zap.Logger, c Capture) (costIn, costOut float64) {
	info, ok := solprovider.GetModelInfo(c.ProviderCatalogID, c.Model)
	tokenPriced := ok && info.Cost != nil && (c.TokensIn > 0 || c.TokensOut > 0)

	if tokenPriced {
		rate := info.Cost
		// Split cached input at the cache-read rate when both the
		// breakdown and a distinct rate are known; otherwise price all
		// input tokens at the standard input rate.
		if c.TokensCached > 0 && rate.CacheRead > 0 {
			nonCached := c.TokensIn - c.TokensCached
			if nonCached < 0 {
				nonCached = 0
			}
			costIn = (float64(nonCached)*rate.Input + float64(c.TokensCached)*rate.CacheRead) / 1e6
		} else {
			costIn = float64(c.TokensIn) * rate.Input / 1e6
		}
		costOut = float64(c.TokensOut) * rate.Output / 1e6
		return costIn, costOut
	}

	if c.UnitKind != "" && c.Units > 0 {
		rate, err := q.GetLLMUnitRate(ctx, dbq.GetLLMUnitRateParams{
			ProviderCatalogID: c.ProviderCatalogID,
			Model:             c.Model,
			UnitKind:          c.UnitKind,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				warnOnce(logger, "nounitrate:"+c.ProviderCatalogID+"/"+c.Model+"/"+c.UnitKind,
					"llm usage: no unit rate configured — recording units with cost 0",
					zap.String("provider", c.ProviderCatalogID),
					zap.String("model", c.Model),
					zap.String("unit_kind", c.UnitKind))
			} else {
				logger.Warn("llm usage: unit-rate lookup failed", zap.Error(err))
			}
			return 0, 0
		}
		return c.Units * rate, 0
	}

	// Token model with no catalog cost data: record the row with cost 0,
	// surfaced once so the misconfiguration is visible.
	if c.TokensIn > 0 || c.TokensOut > 0 {
		warnOnce(logger, "nocost:"+c.ProviderCatalogID+"/"+c.Model,
			"llm usage: model has no token cost in catalog — recording tokens with cost 0",
			zap.String("provider", c.ProviderCatalogID), zap.String("model", c.Model))
	}
	return 0, 0
}
