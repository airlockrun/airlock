package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/goai/message"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// decodeToolOutput resolves a stream tool-result/error "output" payload
// (the discriminated ToolResultOutput union) to (display text, outcome,
// error text). outcome is "success" | "error" | "denied". A nil/empty
// output is treated as an empty success; a malformed one yields the raw
// bytes as text with a success outcome (no legacy-shape handling — the
// data migration converts all history to the new shape).
func DecodeToolOutput(raw json.RawMessage) (text, outcome, errText string) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", "success", ""
	}
	o, err := message.UnmarshalOutput(raw)
	if err != nil {
		return string(raw), "success", ""
	}
	text = message.ToolOutputText(o)
	outcome = message.ToolOutcome(o)
	if outcome == "error" {
		// Error goes solely in errText so the WS event leaves Output
		// empty — mirrors the persisted-refresh path (messageGroup.ts),
		// where an error sets only the block's `error`. Populating both
		// makes ToolBadge render the message twice (black + red).
		return "", "error", text
	}
	return text, outcome, ""
}

func NewCompactionFinishedEvent(runID string, raw json.RawMessage) *airlockv1.CompactionFinishedEvent {
	var finished struct {
		TokensFreed int32  `json:"tokensFreed"`
		Error       string `json:"error"`
	}
	json.Unmarshal(raw, &finished)
	return &airlockv1.CompactionFinishedEvent{
		RunId:       runID,
		TokensFreed: finished.TokensFreed,
		Error:       finished.Error,
	}
}

// runStatusForFallback returns the runs row's current status string, or
// "" if it can't be read. Used to decide whether PublishRunEvents should
// emit a fallback run.error after the agent stream ends mid-flight.
// db may be nil in tests that don't wire a pool; treat that as "unknown"
// and let the caller fall back to the conservative emit-anyway path.
func runStatusForFallback(ctx context.Context, db *pgxpool.Pool, runID uuid.UUID) string {
	if db == nil {
		return ""
	}
	q := dbq.New(db)
	run, err := q.GetRunByID(ctx, toPgUUID(runID))
	if err != nil {
		return ""
	}
	return run.Status
}

// PublishRunEvents reads NDJSON from body, publishes typed proto events to WS,
// accumulates the assistant response text, and returns it along with token usage.
// This runs in a goroutine after the HTTP response has been sent.
//
// User and conversation routing are loaded from the admitted run's immutable
// origin. Neither transport arguments nor streamed payloads can select recipients.
func PublishRunEvents(
	ctx context.Context,
	body io.ReadCloser,
	pubsub *realtime.PubSub,
	db *pgxpool.Pool,
	agentID, runID uuid.UUID,
	logger *zap.Logger,
) (responseText string, newMessages []message.Message, tokensIn, tokensOut int32) {
	defer body.Close()
	if db == nil {
		panic("runtime: event database is required")
	}
	q := dbq.New(db)
	run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: toPgUUID(runID), AgentID: toPgUUID(agentID)})
	if err != nil {
		return
	}
	o, err := q.GetRunOrigin(ctx, run.ID)
	if err != nil || o.Actor != "user" || !o.UserID.Valid || o.AgentID != run.AgentID {
		return
	}
	userID := uuid.UUID(o.UserID.Bytes).String()
	conversationID := ""
	if o.ConversationID.Valid {
		conversationID = uuid.UUID(o.ConversationID.Bytes).String()
	}

	topicID := agentID.String()

	// Every event retains the admitted run's exact recipient tuple.
	mirror := func(eventType string, payload proto.Message) {
		env := realtime.NewEnvelopeForUser(eventType, topicID, userID, conversationID, payload)
		_ = pubsub.Publish(ctx, agentID, env)
	}

	// Emit run started.
	mirror("run.started", &airlockv1.RunStartedEvent{
		RunId:          runID.String(),
		AgentId:        agentID.String(),
		ConversationId: conversationID,
	})

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // 10MB max line for base64 file content
	var sb strings.Builder
	var sawFinish, sawSuspended, sawError bool

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(line, &event) != nil {
			continue
		}

		switch event.Type {
		case "text-delta":
			var delta struct {
				Text string `json:"text"`
			}
			json.Unmarshal(event.Data, &delta)
			sb.WriteString(delta.Text)
			mirror("run.text_delta", &airlockv1.TextDeltaEvent{
				RunId: runID.String(),
				Text:  delta.Text,
			})

		case "compaction_started":
			mirror("run.compaction_started", &airlockv1.CompactionStartedEvent{
				RunId: runID.String(),
			})

		case "compaction_finished":
			mirror("run.compaction_finished", NewCompactionFinishedEvent(runID.String(), event.Data))

		case "tool-call":
			var tc struct {
				ToolCallID string          `json:"toolCallId"`
				ToolName   string          `json:"toolName"`
				Input      json.RawMessage `json:"input"`
			}
			json.Unmarshal(event.Data, &tc)
			mirror("run.tool_call", &airlockv1.ToolCallEvent{
				RunId:      runID.String(),
				ToolCallId: tc.ToolCallID,
				ToolName:   tc.ToolName,
				Input:      string(tc.Input),
			})

		case "tool-result", "tool-error":
			var tr struct {
				ToolCallID string          `json:"toolCallId"`
				ToolName   string          `json:"toolName"`
				Output     json.RawMessage `json:"output"`
			}
			json.Unmarshal(event.Data, &tr)
			out, outcome, errText := DecodeToolOutput(tr.Output)
			mirror("run.tool_result", &airlockv1.ToolResultEvent{
				RunId:      runID.String(),
				ToolCallId: tr.ToolCallID,
				ToolName:   tr.ToolName,
				Output:     out,
				Error:      errText,
				Outcome:    outcome,
			})

		case "tool-output-denied":
			var td struct {
				ToolCallID string `json:"toolCallId"`
				ToolName   string `json:"toolName"`
				Reason     string `json:"reason"`
			}
			json.Unmarshal(event.Data, &td)
			out := td.Reason
			if out == "" {
				out = "Tool call execution denied."
			}
			mirror("run.tool_result", &airlockv1.ToolResultEvent{
				RunId:      runID.String(),
				ToolCallId: td.ToolCallID,
				ToolName:   td.ToolName,
				Output:     out,
				Outcome:    "denied",
			})

		case "confirmation_required":
			var cr struct {
				Permission string         `json:"permission"`
				Patterns   []string       `json:"patterns"`
				Code       string         `json:"code"`
				ToolCallID string         `json:"toolCallId"`
				Metadata   map[string]any `json:"metadata"`
			}
			json.Unmarshal(event.Data, &cr)
			desc, _ := cr.Metadata["description"].(string)
			mirror("run.confirmation_required", &airlockv1.ConfirmationRequiredEvent{
				RunId:       runID.String(),
				Permission:  cr.Permission,
				Patterns:    cr.Patterns,
				Code:        cr.Code,
				ToolCallId:  cr.ToolCallID,
				Description: desc,
			})

		case "suspended":
			sawSuspended = true
			var s struct {
				Reason string `json:"reason"`
			}
			json.Unmarshal(event.Data, &s)
			mirror("run.suspended", &airlockv1.RunSuspendedEvent{
				RunId:  runID.String(),
				Reason: s.Reason,
			})

		case "finish":
			sawFinish = true
			// goai emits ai-sdk v3 usage: inputTokens.total / outputTokens.total
			// are the canonical totals; all fields are optional pointers, so
			// treat missing/null as zero for analytics emission.
			var finish struct {
				FinishReason string `json:"finishReason"`
				Usage        struct {
					InputTokens struct {
						Total *int `json:"total"`
					} `json:"inputTokens"`
					OutputTokens struct {
						Total *int `json:"total"`
					} `json:"outputTokens"`
				} `json:"usage"`
			}
			json.Unmarshal(event.Data, &finish)
			if t := finish.Usage.InputTokens.Total; t != nil {
				tokensIn = int32(*t)
			}
			if t := finish.Usage.OutputTokens.Total; t != nil {
				tokensOut = int32(*t)
			}
			mirror("run.complete", &airlockv1.RunCompleteEvent{
				RunId:        runID.String(),
				FinishReason: finish.FinishReason,
				TokensIn:     tokensIn,
				TokensOut:    tokensOut,
			})

		case "messages":
			var msgs []message.Message
			if err := json.Unmarshal(event.Data, &msgs); err != nil {
				logger.Error("unmarshal messages event", zap.Error(err))
			} else {
				newMessages = msgs
				logger.Info("received messages event",
					zap.Int("count", len(msgs)),
					zap.String("runId", runID.String()))
			}

		case "error":
			sawError = true
			var errEvent struct {
				Message string `json:"message"`
				Error   string `json:"error"`
			}
			json.Unmarshal(event.Data, &errEvent)
			errMsg := errEvent.Error
			if errMsg == "" {
				errMsg = errEvent.Message
			}
			mirror("run.error", &airlockv1.RunErrorEvent{
				RunId: runID.String(),
				Error: errMsg,
			})
		}
	}

	if err := scanner.Err(); err != nil && err != context.Canceled {
		logger.Error("NDJSON scan error", zap.Error(err))
	}

	// If the stream ended without a terminal event (finish / error /
	// suspend), the run may still be alive (agent crashed without calling
	// RunComplete → frontend would hang), OR it may already be finalized
	// by a parallel path (CancelRun handler wrote status='cancelled',
	// agent's detached RunComplete POST landed first, etc.) — those paths
	// publish their own WS terminal event via PublishRunTerminal, so a
	// second one from here is double-emission and a misleading WARN.
	//
	// Resolve the ambiguity by reading the run's current status. Anything
	// non-'running' means somebody else owns the terminal event; emit
	// nothing and log at INFO. 'running' is the genuine "agent died silently"
	// case and cannot establish successful completion.
	if !sawFinish && !sawSuspended && !sawError {
		status := runStatusForFallback(ctx, db, runID)
		switch status {
		case "", "running":
			logger.Warn("agent stream ended without terminal event; emitting run.error fallback",
				zap.String("runId", runID.String()),
				zap.String("agentId", agentID.String()),
				zap.String("dbStatus", status))
			mirror("run.error", &airlockv1.RunErrorEvent{
				RunId: runID.String(),
				Error: "agent stream ended without terminal event",
			})
		default:
			logger.Info("agent stream ended without terminal event; run already finalized — skipping WS fallback",
				zap.String("runId", runID.String()),
				zap.String("agentId", agentID.String()),
				zap.String("dbStatus", status))
		}
	}

	// Clear the replay buffer after terminal events so reconnecting clients
	// don't replay stale text_delta/tool_call events — the DB is the source
	// of truth for historical messages. Suspended runs keep the buffer so a
	// late-joining client can catch up on the in-progress confirmation flow.
	if !sawSuspended {
		pubsub.ClearTopicBuffer(agentID)
	}

	responseText = sb.String()
	return
}
