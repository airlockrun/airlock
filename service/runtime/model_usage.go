package runtime

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/llmledger"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/airlockrun/goai/stream"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// llmUsageCapture is the per-call observation the proxy hands to the
// ledger. Token fields come from stream.FinishEvent.Usage (streaming) or
// the model result's Usage (non-streaming); unit fields carry image/audio
// quantities the token catalog cannot price.
type LlmUsageCapture struct {
	ProviderCatalogID string
	ProviderSlug      string
	Model             string
	Capability        string
	Slug              string

	TokensIn        int64
	TokensOut       int64
	TokensCached    int64
	TokensReasoning int64

	Units    float64
	UnitKind string // "" | "image" | "character" | "second"

	FinishReason        string
	Errored             bool
	Latency             time.Duration
	TaskTokensAccounted bool
	TaskOwnerToken      uuid.UUID
	TaskUsageID         uuid.UUID
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
func (c *LlmUsageCapture) fromStreamUsage(u stream.Usage) {
	c.TokensIn = int64(u.InputTotal())
	c.TokensOut = int64(u.OutputTotal())
	if u.InputTokens.CacheRead != nil {
		c.TokensCached = int64(*u.InputTokens.CacheRead)
	}
	if u.OutputTokens.Reasoning != nil {
		c.TokensReasoning = int64(*u.OutputTokens.Reasoning)
	}
}

// RecordLLMUsage writes best-effort analytics and settles task token budgets.
// A supplied run must resolve exactly; missing attribution cannot bypass a task
// budget. Budget failures are returned to the caller. An independent bounded
// context records incurred spend when a client disconnects.
func (h *Service) RecordLLMUsage(agentID uuid.UUID, runIDHeader string, c LlmUsageCapture) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	q := dbq.New(h.db.Pool())

	var (
		runID    pgtype.UUID
		convID   pgtype.UUID
		userID   pgtype.UUID
		callKind = "unattributed"
		task     bool
	)

	if runIDHeader != "" {
		ru, err := parseUUID(runIDHeader)
		if err != nil {
			return err
		}
		run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: toPgUUID(ru), AgentID: toPgUUID(agentID)})
		if err != nil {
			return err
		}
		runID = toPgUUID(ru)
		callKind = run.TriggerType
		if run.ExecutionKind == "agent" {
			task = true
			convID, userID = run.CallerConversationID, run.CallerUserID
		}
		// Chat-attached runs carry the
		// conversation id in trigger_ref; cron/webhook/code use a
		// non-uuid ref and resolve to no conversation (correct).
		if cu, perr := parseUUID(run.TriggerRef); perr == nil {
			if conv, cerr := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
				ID: toPgUUID(cu), AgentID: toPgUUID(agentID),
			}); cerr == nil {
				convID = conv.ID
				userID = conv.UserID
			}
		}
	}

	llmledger.Record(ctx, q, h.logger, llmledger.Capture{
		AgentID:           toPgUUID(agentID),
		RunID:             runID,
		UserID:            userID,
		ConversationID:    convID,
		ProviderCatalogID: c.ProviderCatalogID,
		ProviderSlug:      c.ProviderSlug,
		Model:             c.Model,
		Capability:        c.Capability,
		CallKind:          callKind,
		Slug:              c.Slug,
		TokensIn:          c.TokensIn,
		TokensOut:         c.TokensOut,
		TokensCached:      c.TokensCached,
		TokensReasoning:   c.TokensReasoning,
		Units:             c.Units,
		UnitKind:          c.UnitKind,
		FinishReason:      c.FinishReason,
		Errored:           c.Errored,
		Latency:           c.Latency,
	})
	if task && !c.TaskTokensAccounted && (c.TokensIn != 0 || c.TokensOut != 0) {
		return execution.RecordAgentTaskUsage(ctx, h.db, agentID, uuid.UUID(runID.Bytes), c.TaskOwnerToken, c.TaskUsageID, c.TokensIn+c.TokensOut, true)
	}
	return nil
}
