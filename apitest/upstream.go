package apitest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Upstream builds an http.Handler that imitates an agent container's
// POST /prompt endpoint by streaming NDJSON events.
//
// Events match the wire format that `trigger.StreamNDJSONResponse`
// reads ([trigger/prompt.go:716+](airlock/trigger/prompt.go#L716)).
// Each event is a single JSON line: {"type":"<kind>","data":{...}}.
//
// Method-chain API:
//
//	apitest.NewUpstream().
//	    TextDelta("Hello ").TextDelta("world").
//	    ToolCall("id-1", "add", `{"a":1,"b":2}`).
//	    ToolResult("id-1", "add", `3`).
//	    Finish().
//	    Handler()
//
// Per-event delay simulates streaming pace; defaults to 0.
type Upstream struct {
	events  []upstreamEvent
	delay   time.Duration
	onError func(w http.ResponseWriter, r *http.Request) bool
}

type upstreamEvent struct {
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

func NewUpstream() *Upstream { return &Upstream{} }

// WithDelay inserts a pause between events to simulate token-by-token
// streaming. Keep test delays under 1ms unless a test is specifically
// asserting timing behaviour.
func (u *Upstream) WithDelay(d time.Duration) *Upstream {
	u.delay = d
	return u
}

func (u *Upstream) TextDelta(text string) *Upstream {
	return u.push("text-delta", map[string]any{"text": text})
}

func (u *Upstream) ToolCall(id, name, inputJSON string) *Upstream {
	return u.push("tool-call", map[string]any{
		"toolCallId": id,
		"toolName":   name,
		"input":      json.RawMessage(inputJSON),
	})
}

func (u *Upstream) ToolResult(id, name, outputJSON string) *Upstream {
	return u.push("tool-result", map[string]any{
		"toolCallId": id,
		"toolName":   name,
		"output":     json.RawMessage(outputJSON),
	})
}

func (u *Upstream) ToolError(id, name, errorText string) *Upstream {
	return u.push("tool-error", map[string]any{
		"toolCallId": id,
		"toolName":   name,
		"output":     map[string]string{"error": errorText},
	})
}

// ConfirmationRequired mirrors the operator-approval signal an agent
// emits before suspending for a tool call.
//
// Note: confirmation_required alone does NOT end the run on airlock's
// side — pair it with Suspend() to mark the run paused.
func (u *Upstream) ConfirmationRequired(toolCallID, permission, code string, patterns ...string) *Upstream {
	return u.push("confirmation_required", map[string]any{
		"toolCallId": toolCallID,
		"permission": permission,
		"code":       code,
		"patterns":   patterns,
	})
}

// Suspend emits the terminal-suspended marker. Use after
// ConfirmationRequired so airlock keeps the WS replay buffer (a
// completion would clear it).
func (u *Upstream) Suspend(reason string) *Upstream {
	return u.push("suspended", map[string]any{"reason": reason})
}

// Finish emits the run-completion event with zero token usage. Tests
// that care about usage accounting should use FinishWithUsage.
func (u *Upstream) Finish() *Upstream {
	return u.FinishWithUsage(0, 0)
}

func (u *Upstream) FinishWithUsage(inputTokens, outputTokens int) *Upstream {
	return u.push("finish", map[string]any{
		"usage": map[string]any{
			"inputTokens":  map[string]any{"total": inputTokens},
			"outputTokens": map[string]any{"total": outputTokens},
		},
	})
}

// Raw lets a test push an event the convenience methods don't cover.
func (u *Upstream) Raw(eventType string, data map[string]any) *Upstream {
	return u.push(eventType, data)
}

func (u *Upstream) push(t string, d map[string]any) *Upstream {
	u.events = append(u.events, upstreamEvent{Type: t, Data: d})
	return u
}

// Handler returns an http.Handler that streams the configured events
// on POST /prompt, or 405 on any other path/method. The response is
// NDJSON: one JSON object per line, flushed after each line so the
// dispatcher's bufio.Scanner sees streaming behaviour.
func (u *Upstream) Handler() http.Handler {
	events := append([]upstreamEvent(nil), u.events...)
	delay := u.delay
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/prompt" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)

		bw := bufio.NewWriter(w)
		enc := json.NewEncoder(bw)
		for _, ev := range events {
			if err := enc.Encode(ev); err != nil {
				return
			}
			if err := bw.Flush(); err != nil {
				return
			}
			flusher.Flush()
			if delay > 0 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(delay):
				}
			}
		}
	})
}

// MarshalEvent is exposed so tests can hand-craft a single NDJSON
// line without spinning up an Upstream — useful for one-off assertions
// against the parser.
func MarshalEvent(eventType string, data map[string]any) []byte {
	line, err := json.Marshal(upstreamEvent{Type: eventType, Data: data})
	if err != nil {
		panic(fmt.Sprintf("apitest: marshal upstream event: %v", err))
	}
	return append(line, '\n')
}
