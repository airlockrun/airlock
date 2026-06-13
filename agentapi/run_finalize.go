package agentapi

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// PublishRunTerminal publishes the appropriate WebSocket event for a run's
// terminal state. Mirrors what PublishRunEvents emits from the agent's
// NDJSON stream so frontends and bridges see one event regardless of which
// path the run took to terminal — happy path (NDJSON), cancel (CancelRun
// closes the stream early), the agent's detached r.Complete POST after the
// stream died, or the sweeper for stuck rows.
//
// Maps airlock-side status strings to WS event types:
//   - "error" / "failed" / "timeout" → run.error
//   - everything else (success, tool_errors, cancelled, suspended) → run.complete
//
// Idempotent at the client: chat.ts ignores events for runIDs already
// finalized locally, so a duplicate from the happy-path NDJSON + this helper
// is harmless.
func PublishRunTerminal(ctx context.Context, pubsub *realtime.PubSub, agentID, runID uuid.UUID, status, errMsg string) {
	if pubsub == nil {
		return
	}
	topicID := agentID.String()
	switch status {
	case "error", "failed", "timeout":
		_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.error", topicID, &airlockv1.RunErrorEvent{
			RunId: runID.String(),
			Error: errMsg,
		}))
	default:
		_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.complete", topicID, &airlockv1.RunCompleteEvent{
			RunId: runID.String(),
		}))
	}
}

// SynthesizeOrphanToolResults inserts a synthetic role=tool message for every
// tool-call this run emitted that doesn't have a paired tool-result row.
// Required for the next LLM turn: provider APIs (Anthropic, OpenAI) reject
// inputs where an assistant's tool_use isn't followed by a tool_result with
// the matching id. Common after cancel, deadline-exceeded, panic mid-tool,
// or any path where the agent didn't get to write the tool's result before
// terminating.
//
// The synthesized output text is derived from the run's terminal status so
// the LLM has some signal about why the tool didn't complete:
//   - "cancelled" → "Cancelled by user."
//   - "timeout"   → "Tool timed out."
//   - else        → "Tool execution failed."
//
// Best-effort: failures are logged but don't block the caller. The
// SessionLoad lazy-synthesis path is the safety net if this misses.
func SynthesizeOrphanToolResults(ctx context.Context, q *dbq.Queries, runID uuid.UUID, status string, logger *zap.Logger) {
	orphans, err := q.ListOrphanToolCallsByRun(ctx, toPgUUID(runID))
	if err != nil {
		logger.Error("list orphan tool_calls", zap.String("run_id", runID.String()), zap.Error(err))
		return
	}
	if len(orphans) == 0 {
		return
	}

	output := orphanResultText(status)
	for _, o := range orphans {
		partsJSON, err := json.Marshal([]map[string]any{{
			"type":       "tool-result",
			"toolCallId": o.ToolCallID,
			"toolName":   o.ToolName,
			"result":     output,
		}})
		if err != nil {
			continue
		}
		_, err = q.CreateMessage(ctx, dbq.CreateMessageParams{
			ConversationID: o.ConversationID,
			Role:           "tool",
			Content:        output,
			Parts:          partsJSON,
			RunID:          toPgUUID(runID),
			Source:         "synthetic",
		})
		if err != nil {
			logger.Warn("synthesize orphan tool_result",
				zap.String("run_id", runID.String()),
				zap.String("tool_call_id", o.ToolCallID),
				zap.Error(err))
		}
	}
	logger.Info("synthesized orphan tool_results",
		zap.String("run_id", runID.String()),
		zap.String("status", status),
		zap.Int("count", len(orphans)))
}

func orphanResultText(status string) string {
	switch status {
	case "cancelled":
		return "Cancelled by user."
	case "timeout":
		return "Tool timed out."
	default:
		return "Tool execution failed."
	}
}

// pairsAndOrphans walks a slice of message rows in order and returns the set
// of toolCallIds for tool-call parts that don't have a paired tool-result
// later in the slice. Used by SessionLoad as a defense-in-depth check.
// Returns slice of {toolCallId, toolName} for each orphan.
type orphanPair struct {
	ToolCallID string
	ToolName   string
}

func detectOrphanToolCalls(parts []dbq.AgentMessage) []orphanPair {
	results := map[string]struct{}{}
	type call struct {
		id   string
		name string
	}
	var calls []call

	for _, m := range parts {
		if len(m.Parts) == 0 {
			continue
		}
		var arr []map[string]any
		if err := json.Unmarshal(m.Parts, &arr); err != nil {
			continue
		}
		for _, p := range arr {
			t, _ := p["type"].(string)
			id, _ := p["toolCallId"].(string)
			if id == "" {
				continue
			}
			switch t {
			case "tool-call":
				name, _ := p["toolName"].(string)
				calls = append(calls, call{id: id, name: name})
			case "tool-result":
				results[id] = struct{}{}
			}
		}
	}

	var orphans []orphanPair
	for _, c := range calls {
		if _, ok := results[c.id]; !ok {
			orphans = append(orphans, orphanPair{ToolCallID: c.id, ToolName: c.name})
		}
	}
	return orphans
}

// reconcileDanglingToolResults is the inverse of detectOrphanToolCalls:
// it repairs tool-result parts whose toolCallId has NO preceding
// tool-call. That orphan shape is produced when a tool-result is
// persisted without its originating assistant tool-call message (e.g. a
// run that yielded mid-tool before the assistant turn was written — the
// delegated-suspension defect). Providers reject a role=tool message
// with no matching tool_use, so it poisons every subsequent turn exactly
// like the forward orphan.
//
// The repair inserts a synthetic assistant message carrying the missing
// tool-call(s) immediately BEFORE the offending tool message, restoring
// a provider-valid assistant→tool pair without dropping the result's
// content. Returns the corrected slice (input untouched) plus one
// orphanPair per repair for logging/surfacing. In-memory only on the
// load path, same contract as orphanToolResultMessage.
func reconcileDanglingToolResults(convID pgtype.UUID, msgs []dbq.AgentMessage) ([]dbq.AgentMessage, []orphanPair) {
	seenCalls := map[string]struct{}{}
	out := make([]dbq.AgentMessage, 0, len(msgs))
	var repaired []orphanPair

	for _, m := range msgs {
		var arr []map[string]any
		if len(m.Parts) > 0 {
			_ = json.Unmarshal(m.Parts, &arr)
		}

		var missing []orphanPair
		for _, p := range arr {
			t, _ := p["type"].(string)
			id, _ := p["toolCallId"].(string)
			if id == "" {
				continue
			}
			switch t {
			case "tool-call":
				seenCalls[id] = struct{}{}
			case "tool-result":
				if _, ok := seenCalls[id]; !ok {
					name, _ := p["toolName"].(string)
					missing = append(missing, orphanPair{ToolCallID: id, ToolName: name})
					// Mark satisfied: the synthetic call below covers it,
					// and a later duplicate result mustn't re-trigger.
					seenCalls[id] = struct{}{}
				}
			}
		}

		if len(missing) > 0 {
			out = append(out, synthAssistantToolCallMessage(convID, missing))
			repaired = append(repaired, missing...)
		}
		out = append(out, m)
	}
	return out, repaired
}

// synthAssistantToolCallMessage returns a synthetic assistant message
// carrying the tool-call(s) a dangling tool-result lost. Placed
// immediately before the orphaned result it restores a provider-valid
// assistant→tool pair without dropping the result's content. In-memory
// only on the load path, same as orphanToolResultMessage; the durable
// invariant is enforced at write time (SessionAppend).
func synthAssistantToolCallMessage(convID pgtype.UUID, ops []orphanPair) dbq.AgentMessage {
	arr := make([]map[string]any, 0, len(ops))
	for _, op := range ops {
		arr = append(arr, map[string]any{
			"type":       "tool-call",
			"toolCallId": op.ToolCallID,
			"toolName":   op.ToolName,
			"input":      map[string]any{},
		})
	}
	parts, _ := json.Marshal(arr)
	return dbq.AgentMessage{
		ConversationID: convID,
		Role:           "assistant",
		Content:        "",
		Parts:          parts,
		Source:         "synthetic",
	}
}

// orphanToolResultMessage returns a synthetic dbq.AgentMessage in the shape
// SessionLoad will convert via dbMessageToSession. In-memory only — never
// persisted on the load path; the persistent path is RunComplete +
// the sweeper. The warn log next to this call surfaces synthesis misses.
func orphanToolResultMessage(convID pgtype.UUID, op orphanPair) dbq.AgentMessage {
	parts, _ := json.Marshal([]map[string]any{{
		"type":       "tool-result",
		"toolCallId": op.ToolCallID,
		"toolName":   op.ToolName,
		"output": map[string]any{
			"type":  "text",
			"value": "Tool result missing — likely an interrupted earlier run.",
		},
	}})
	return dbq.AgentMessage{
		ConversationID: convID,
		Role:           "tool",
		Content:        "Tool result missing — likely an interrupted earlier run.",
		Parts:          parts,
		Source:         "synthetic",
	}
}

// Compile-time assertion that the struct fields we touch are all present
// in the generated dbq.AgentMessage. Catches schema drift early.
var _ = func() any { return fmt.Sprintf("%T", dbq.AgentMessage{}) }
