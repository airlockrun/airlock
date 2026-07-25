package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/goai/message"
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
//   - everything else (success, tool_errors, cancelled) -> run.complete
//
// Idempotent at the client: chat.ts ignores events for runIDs already
// finalized locally, so a duplicate from the happy-path NDJSON + this helper
// is harmless.
func PublishRunTerminal(ctx context.Context, pubsub *realtime.PubSub, agentID, runID uuid.UUID, status, errMsg string) {
	if pubsub == nil || status == "suspended" {
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
			"output": map[string]any{
				"type":  "error-text",
				"value": output,
			},
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

type orphanPair struct {
	ToolCallID string
	ToolName   string
}

type rawToolPart struct {
	Pair orphanPair
	Raw  json.RawMessage
}

type toolResultPart struct {
	rawToolPart
	Row  *toolResultRow
	Used bool
}

type toolResultRow struct {
	Message    dbq.AgentMessage
	Extras     []json.RawMessage
	ExtrasUsed bool
	Rewritten  bool
}

type toolCallTurn struct {
	Calls   []orphanPair
	Results []*toolResultPart
}

// normalizeToolOrdering returns a provider-valid model history. Every real
// result is moved directly behind its originating assistant turn, missing
// results are synthesized there, and result rows with no call get a synthetic
// assistant turn at their original position. Provider-valid canonical
// histories are returned unchanged.
func normalizeToolOrdering(convID pgtype.UUID, msgs []dbq.AgentMessage) ([]dbq.AgentMessage, []orphanPair, []orphanPair, error) {
	valid, err := toolOrderingValid(msgs)
	if err != nil {
		return nil, nil, nil, err
	}
	if valid {
		return msgs, nil, nil, nil
	}

	turns := make(map[int]*toolCallTurn)
	resultsByID := make(map[string][]*toolResultPart)
	resultsByRow := make(map[int][]*toolResultPart)
	for i, msg := range msgs {
		if msg.Role == "assistant" {
			calls, _ := parseToolParts(msg.Parts, "tool-call")
			if len(calls) > 0 {
				turn := &toolCallTurn{Calls: make([]orphanPair, len(calls))}
				for j, call := range calls {
					turn.Calls[j] = call.Pair
				}
				turns[i] = turn
			}
		}
		if msg.Role == "tool" {
			row, results, err := parseToolResultRow(msg)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("tool message %d: %w", i, err)
			}
			for _, result := range results {
				part := &toolResultPart{rawToolPart: result, Row: row}
				resultsByID[result.Pair.ToolCallID] = append(resultsByID[result.Pair.ToolCallID], part)
				resultsByRow[i] = append(resultsByRow[i], part)
			}
		}
	}

	resultCursor := make(map[string]int)
	for i := range msgs {
		turn := turns[i]
		if turn == nil {
			continue
		}
		turn.Results = make([]*toolResultPart, len(turn.Calls))
		for j, call := range turn.Calls {
			available := resultsByID[call.ToolCallID]
			cursor := resultCursor[call.ToolCallID]
			if cursor >= len(available) {
				continue
			}
			turn.Results[j] = available[cursor]
			available[cursor].Used = true
			resultCursor[call.ToolCallID] = cursor + 1
		}
	}

	out := make([]dbq.AgentMessage, 0, len(msgs))
	var danglingResults []orphanPair
	var missingResults []orphanPair
	for i, msg := range msgs {
		if turn := turns[i]; turn != nil {
			out = append(out, msg)
			for j, call := range turn.Calls {
				if result := turn.Results[j]; result != nil {
					out = append(out, toolResultMessage(result))
					continue
				}
				out = append(out, orphanToolResultMessage(convID, call))
				missingResults = append(missingResults, call)
			}
			continue
		}
		if msg.Role != "tool" {
			out = append(out, msg)
			continue
		}

		var extras []*toolResultPart
		for _, result := range resultsByRow[i] {
			if !result.Used {
				extras = append(extras, result)
			}
		}
		if len(extras) == 0 {
			continue
		}
		calls := make([]orphanPair, len(extras))
		for j, result := range extras {
			calls[j] = result.Pair
		}
		out = append(out, synthAssistantToolCallMessage(convID, calls))
		for _, result := range extras {
			out = append(out, toolResultMessage(result))
		}
		danglingResults = append(danglingResults, calls...)
	}
	return out, danglingResults, missingResults, nil
}

func toolOrderingValid(msgs []dbq.AgentMessage) (bool, error) {
	var pending []orphanPair
	for i, msg := range msgs {
		if len(pending) > 0 {
			if msg.Role != "tool" {
				return false, nil
			}
			row, results, err := parseToolResultRow(msg)
			if err != nil {
				return false, fmt.Errorf("tool message %d: %w", i, err)
			}
			if row.Rewritten {
				return false, nil
			}
			for _, result := range results {
				if len(pending) == 0 || result.Pair.ToolCallID != pending[0].ToolCallID {
					return false, nil
				}
				pending = pending[1:]
			}
			continue
		}
		if msg.Role == "tool" {
			if _, _, err := parseToolResultRow(msg); err != nil {
				return false, fmt.Errorf("tool message %d: %w", i, err)
			}
			return false, nil
		}
		if msg.Role != "assistant" {
			continue
		}
		calls, _ := parseToolParts(msg.Parts, "tool-call")
		for _, call := range calls {
			pending = append(pending, call.Pair)
		}
	}
	return len(pending) == 0, nil
}

func parseToolParts(parts []byte, wantType string) ([]rawToolPart, bool) {
	if len(parts) == 0 {
		return nil, true
	}
	var rawParts []json.RawMessage
	if err := json.Unmarshal(parts, &rawParts); err != nil {
		return nil, false
	}
	parsed := make([]rawToolPart, 0, len(rawParts))
	for _, raw := range rawParts {
		var part struct {
			Type       string `json:"type"`
			ToolCallID string `json:"toolCallId"`
			ToolName   string `json:"toolName"`
		}
		if err := json.Unmarshal(raw, &part); err != nil {
			continue
		}
		if part.Type == wantType && part.ToolCallID != "" {
			parsed = append(parsed, rawToolPart{
				Pair: orphanPair{ToolCallID: part.ToolCallID, ToolName: part.ToolName},
				Raw:  raw,
			})
		}
	}
	return parsed, true
}

func parseToolResultRow(msg dbq.AgentMessage) (*toolResultRow, []rawToolPart, error) {
	if len(msg.Parts) == 0 {
		return nil, nil, errors.New("tool message has no parts")
	}
	var rawParts []json.RawMessage
	if err := json.Unmarshal(msg.Parts, &rawParts); err != nil {
		return nil, nil, fmt.Errorf("invalid parts: %w", err)
	}
	row := &toolResultRow{Message: msg}
	normalizedParts := make([]json.RawMessage, 0, len(rawParts))
	var results []rawToolPart
	for _, raw := range rawParts {
		var part struct {
			Type       string `json:"type"`
			ToolCallID string `json:"toolCallId"`
			ToolName   string `json:"toolName"`
		}
		if err := json.Unmarshal(raw, &part); err != nil {
			return nil, nil, fmt.Errorf("invalid part: %w", err)
		}
		if part.Type != "tool-result" {
			row.Extras = append(row.Extras, raw)
			normalizedParts = append(normalizedParts, raw)
			continue
		}
		if part.ToolCallID == "" {
			return nil, nil, errors.New("tool-result part has no toolCallId")
		}
		normalized, rewritten, err := normalizePersistedToolResult(raw)
		if err != nil {
			return nil, nil, err
		}
		if rewritten {
			row.Rewritten = true
			raw = normalized
		}
		normalizedParts = append(normalizedParts, raw)
		results = append(results, rawToolPart{
			Pair: orphanPair{ToolCallID: part.ToolCallID, ToolName: part.ToolName},
			Raw:  raw,
		})
	}
	if row.Rewritten {
		row.Message.Parts, _ = json.Marshal(normalizedParts)
	}
	var content message.Content
	if err := json.Unmarshal(row.Message.Parts, &content); err != nil {
		return nil, nil, fmt.Errorf("invalid parts: %w", err)
	}
	if len(results) == 0 {
		return nil, nil, errors.New("tool message has no tool-result parts")
	}
	return row, results, nil
}

func normalizePersistedToolResult(raw json.RawMessage) (json.RawMessage, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false, fmt.Errorf("invalid tool-result part: %w", err)
	}
	_, hasOutput := fields["output"]
	resultRaw, hasResult := fields["result"]
	if hasOutput {
		if hasResult {
			return nil, false, errors.New("tool-result part has both output and result")
		}
		return raw, false, nil
	}
	if !hasResult {
		return nil, false, errors.New("tool-result part has neither output nor result")
	}

	var result string
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return nil, false, fmt.Errorf("tool-result result must be a string: %w", err)
	}
	isError := false
	if isErrorRaw, ok := fields["isError"]; ok {
		var value *bool
		if err := json.Unmarshal(isErrorRaw, &value); err != nil || value == nil {
			return nil, false, errors.New("tool-result isError must be a boolean")
		}
		isError = *value
	}

	var output message.ToolResultOutput = message.TextOutput{Value: result}
	if isError {
		output = message.ErrorTextOutput{Value: result}
	}
	outputRaw, err := message.MarshalOutput(output)
	if err != nil {
		return nil, false, fmt.Errorf("marshal tool-result output: %w", err)
	}
	fields["output"] = outputRaw
	delete(fields, "result")
	delete(fields, "isError")
	normalized, err := json.Marshal(fields)
	if err != nil {
		return nil, false, fmt.Errorf("marshal tool-result part: %w", err)
	}
	return normalized, true, nil
}

func toolResultMessage(result *toolResultPart) dbq.AgentMessage {
	msg := result.Row.Message
	parts := []json.RawMessage{result.Raw}
	if !result.Row.ExtrasUsed {
		parts = append(parts, result.Row.Extras...)
		result.Row.ExtrasUsed = true
	}
	msg.Parts, _ = json.Marshal(parts)
	return msg
}

// ValidateSuspendedCheckpoint validates the wire fields Airlock needs before a
// suspended run can become resumable. It intentionally does not depend on Sol.
func ValidateSuspendedCheckpoint(checkpoint []byte) error {
	var wire struct {
		SuspensionContext *struct {
			Reason string `json:"reason"`
		} `json:"suspensionContext"`
	}
	if len(checkpoint) == 0 {
		return errors.New("checkpoint is required")
	}
	if err := json.Unmarshal(checkpoint, &wire); err != nil {
		return fmt.Errorf("checkpoint must be a JSON object: %w", err)
	}
	if wire.SuspensionContext == nil {
		return errors.New("checkpoint suspensionContext is required")
	}
	reason := strings.TrimSpace(wire.SuspensionContext.Reason)
	switch reason {
	case "permission", "delegated":
		return nil
	case "":
		return errors.New("checkpoint suspensionContext reason is required")
	default:
		return fmt.Errorf("checkpoint suspensionContext reason %q is not supported", reason)
	}
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
			"args":       map[string]any{},
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
			"type":  "error-text",
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
