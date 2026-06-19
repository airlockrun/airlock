package agentapi

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/llmledger"
	"github.com/airlockrun/goai/stream"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// llmUsageCapture is the per-call observation the proxy hands to the
// ledger. Token fields come from stream.FinishEvent.Usage (streaming) or
// the model result's Usage (non-streaming); unit fields carry image/audio
// quantities the token catalog cannot price.
type llmUsageCapture struct {
	providerCatalogID string
	providerSlug      string
	model             string
	capability        string
	slug              string

	tokensIn        int64
	tokensOut       int64
	tokensCached    int64
	tokensReasoning int64

	units    float64
	unitKind string // "" | "image" | "character" | "second"

	finishReason string
	errored      bool
	latency      time.Duration
}

// normalizeCapability maps the empty capability (resolveModel's "text"
// default) to the explicit "text" label so the ledger never stores "".
func normalizeCapability(c string) string {
	if c == "" {
		return "text"
	}
	return c
}

// fromStreamUsage fills the token fields from an accumulated stream.Usage.
func (c *llmUsageCapture) fromStreamUsage(u stream.Usage) {
	c.tokensIn = int64(u.InputTotal())
	c.tokensOut = int64(u.OutputTotal())
	if u.InputTokens.CacheRead != nil {
		c.tokensCached = int64(*u.InputTokens.CacheRead)
	}
	if u.OutputTokens.Reasoning != nil {
		c.tokensReasoning = int64(*u.OutputTokens.Reasoning)
	}
}

// recordLLMUsage writes one append-only llm_usage row. Best-effort: every
// failure is logged and swallowed — accounting must never break a model
// call that already succeeded for the agent. runIDHeader is the
// X-Airlock-Run-ID value (may be ""); attribution degrades to an
// unattributed row rather than dropping the spend. Uses a fresh bounded
// context so a client that disconnected mid-stream still gets its
// already-incurred spend recorded.
func (h *Handler) recordLLMUsage(agentID uuid.UUID, runIDHeader string, c llmUsageCapture) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	q := dbq.New(h.db.Pool())

	var (
		runID    pgtype.UUID
		convID   pgtype.UUID
		userID   pgtype.UUID
		callKind = "unattributed"
	)

	if runIDHeader != "" {
		if ru, err := parseUUID(runIDHeader); err == nil {
			if run, rerr := q.GetRunByID(ctx, toPgUUID(ru)); rerr == nil {
				runID = toPgUUID(ru)
				callKind = run.TriggerType
				// Chat-attached runs (prompt/a2a/bridge) carry the
				// conversation id in trigger_ref; cron/webhook/code use a
				// non-uuid ref and resolve to no conversation (correct).
				if cu, perr := parseUUID(run.TriggerRef); perr == nil {
					if conv, cerr := q.GetConversationByID(ctx, toPgUUID(cu)); cerr == nil {
						convID = conv.ID
						userID = conv.UserID
					}
				}
			}
		}
	}

	llmledger.Record(ctx, q, h.logger, llmledger.Capture{
		AgentID:           toPgUUID(agentID),
		RunID:             runID,
		UserID:            userID,
		ConversationID:    convID,
		ProviderCatalogID: c.providerCatalogID,
		ProviderSlug:      c.providerSlug,
		Model:             c.model,
		Capability:        c.capability,
		CallKind:          callKind,
		Slug:              c.slug,
		TokensIn:          c.tokensIn,
		TokensOut:         c.tokensOut,
		TokensCached:      c.tokensCached,
		TokensReasoning:   c.tokensReasoning,
		Units:             c.units,
		UnitKind:          c.unitKind,
		FinishReason:      c.finishReason,
		Errored:           c.errored,
		Latency:           c.latency,
	})
}
