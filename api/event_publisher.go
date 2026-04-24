package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/goai/message"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// publishRunEvents reads NDJSON from body, publishes typed proto events to WS,
// accumulates the assistant response text, and returns it along with token usage.
// This runs in a goroutine after the HTTP response has been sent.
func publishRunEvents(
	ctx context.Context,
	body io.ReadCloser,
	pubsub *realtime.PubSub,
	agentID, runID uuid.UUID,
	conversationID string,
	logger *zap.Logger,
) (responseText string, newMessages []message.Message, tokensIn, tokensOut int32) {
	defer body.Close()

	topicID := agentID.String()

	// Emit run started.
	_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.started", topicID, &airlockv1.RunStartedEvent{
		RunId:          runID.String(),
		AgentId:        agentID.String(),
		ConversationId: conversationID,
	}))

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
			_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.text_delta", topicID, &airlockv1.TextDeltaEvent{
				RunId: runID.String(),
				Text:  delta.Text,
			}))

		case "tool-call":
			var tc struct {
				ToolCallID string          `json:"toolCallId"`
				ToolName   string          `json:"toolName"`
				Input      json.RawMessage `json:"input"`
			}
			json.Unmarshal(event.Data, &tc)
			_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.tool_call", topicID, &airlockv1.ToolCallEvent{
				RunId:      runID.String(),
				ToolCallId: tc.ToolCallID,
				ToolName:   tc.ToolName,
				Input:      string(tc.Input),
			}))

		case "tool-result":
			var tr struct {
				ToolCallID string          `json:"toolCallId"`
				ToolName   string          `json:"toolName"`
				Output     json.RawMessage `json:"output"`
			}
			json.Unmarshal(event.Data, &tr)
			// Output may be a JSON string or a ToolOutput object with an "output" field.
			var output string
			if json.Unmarshal(tr.Output, &output) != nil {
				var toolOutput struct {
					Output string `json:"output"`
				}
				if json.Unmarshal(tr.Output, &toolOutput) == nil {
					output = toolOutput.Output
				} else {
					output = string(tr.Output)
				}
			}
			_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.tool_result", topicID, &airlockv1.ToolResultEvent{
				RunId:      runID.String(),
				ToolCallId: tr.ToolCallID,
				ToolName:   tr.ToolName,
				Output:     output,
			}))

		case "tool-error":
			var te struct {
				ToolCallID string `json:"toolCallId"`
				ToolName   string `json:"toolName"`
				Error      string `json:"error"`
			}
			json.Unmarshal(event.Data, &te)
			_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.tool_result", topicID, &airlockv1.ToolResultEvent{
				RunId:      runID.String(),
				ToolCallId: te.ToolCallID,
				ToolName:   te.ToolName,
				Error:      te.Error,
			}))

		case "confirmation_required":
			var cr struct {
				Permission string   `json:"permission"`
				Patterns   []string `json:"patterns"`
				Code       string   `json:"code"`
				ToolCallID string   `json:"toolCallId"`
			}
			json.Unmarshal(event.Data, &cr)
			_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.confirmation_required", topicID, &airlockv1.ConfirmationRequiredEvent{
				RunId:      runID.String(),
				Permission: cr.Permission,
				Patterns:   cr.Patterns,
				Code:       cr.Code,
				ToolCallId: cr.ToolCallID,
			}))

		case "suspended":
			sawSuspended = true
			var s struct {
				Reason string `json:"reason"`
			}
			json.Unmarshal(event.Data, &s)
			_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.suspended", topicID, &airlockv1.RunSuspendedEvent{
				RunId:  runID.String(),
				Reason: s.Reason,
			}))

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
			_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.complete", topicID, &airlockv1.RunCompleteEvent{
				RunId:        runID.String(),
				FinishReason: finish.FinishReason,
				TokensIn:     tokensIn,
				TokensOut:    tokensOut,
			}))

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
			_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.error", topicID, &airlockv1.RunErrorEvent{
				RunId: runID.String(),
				Error: errMsg,
			}))
		}
	}

	if err := scanner.Err(); err != nil && err != context.Canceled {
		logger.Error("NDJSON scan error", zap.Error(err))
	}

	// If the stream ended without a terminal event (finish / error / suspend),
	// emit a run.complete fallback so the frontend unblocks. Errors and
	// suspensions already deliver their own terminal events — firing a
	// second run.complete on top would confuse the chat store into
	// double-finalizing.
	if !sawFinish && !sawSuspended && !sawError {
		logger.Warn("agent stream ended without terminal event — emitting run.complete fallback",
			zap.String("runId", runID.String()), zap.String("agentId", agentID.String()))
		_ = pubsub.Publish(ctx, agentID, realtime.NewEnvelope("run.complete", topicID, &airlockv1.RunCompleteEvent{
			RunId:        runID.String(),
			FinishReason: "stop",
		}))
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
