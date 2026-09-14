package agentapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/airlockrun/airlock/apperr"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	goaierrors "github.com/airlockrun/goai/errors"
	"github.com/airlockrun/goai/stream"
	"go.uber.org/zap"
)

// LLMStream handles POST /api/agent/llm/stream.
func (h *Handler) LLMStream(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	var req wire.LLMProxyRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().LLMStream(callbackContext(r), r.Header.Get("X-Airlock-Run-ID"), req)
	if err != nil {
		setLLMStreamErrorHeaders(w.Header(), err)
		status := apperr.HTTPStatus(err)
		message := err.Error()
		if status == http.StatusInternalServerError {
			status = llmStreamErrorStatus(err)
			h.logger.Error("LLM stream failed", zap.Error(err))
			message = "LLM stream failed"
		}
		writeJSONError(w, status, message)
		return
	}
	events := result.Events

	// Some providers perform HTTP setup inside the returned stream. Hold their
	// initial Start event until setup is confirmed so a pre-content ErrorEvent
	// can still be returned as an HTTP error for the caller's retry policy.
	pending, setupErr := awaitLLMStreamSetup(r.Context(), events)
	if setupErr != nil {
		h.logger.Error("LLM stream setup failed", zap.Error(setupErr))
		setLLMStreamErrorHeaders(w.Header(), setupErr)
		writeJSONError(w, llmStreamErrorStatus(setupErr), "LLM stream failed")
		return
	}

	// Write NDJSON response once provider setup has succeeded.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)

	bw := bufio.NewWriter(w)
	flusher, canFlush := w.(http.Flusher)

	writeEvent := func(event stream.Event) {
		nd := ndJSONEvent{
			Type: string(event.Type),
			Data: sanitizeEventData(event.Data),
		}

		// ErrorEvent.Error is an `error` — not JSON-serializable. Convert to string.
		// Log mid-stream errors so platform-side LLM failures (provider 4xx, network
		// blips, etc.) show up in airlock logs instead of being silently relayed
		// to the agent as opaque NDJSON.
		if ee, ok := event.Data.(stream.ErrorEvent); ok {
			h.logger.Warn("LLM stream error",
				zap.String("provider", result.Provider),
				zap.String("model", result.Model),
				zap.String("agent", agentID.String()),
				zap.Error(ee.Error),
			)
			nd.Data = map[string]string{"error": ee.Error.Error()}
		}

		line, err := json.Marshal(nd)
		if err != nil {
			// A single malformed event must not abort the entire stream —
			// the agent would read EOF and time out (surfaced to the user
			// as "context deadline exceeded"). Skip this event and keep
			// going; the run continues with the next one.
			h.logger.Error("marshal NDJSON event failed — skipping event",
				zap.String("event_type", string(event.Type)),
				zap.Error(err))
			return
		}
		bw.Write(line)
		bw.WriteByte('\n')
		bw.Flush()
		if canFlush {
			flusher.Flush()
		}
	}
	for _, event := range pending {
		writeEvent(event)
	}
	for event := range events {
		writeEvent(event)
	}
}

func llmStreamErrorStatus(err error) int {
	var apiErr *goaierrors.APICallError
	if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode <= 599 {
		return apiErr.StatusCode
	}
	return http.StatusBadGateway
}

func llmStreamErrorRetryable(err error) bool {
	var apiErr *goaierrors.APICallError
	return errors.As(err, &apiErr) && apiErr.IsRetryable
}

func setLLMStreamErrorHeaders(header http.Header, err error) {
	header.Set("X-Airlock-LLM-Retryable", strconv.FormatBool(llmStreamErrorRetryable(err)))
	var apiErr *goaierrors.APICallError
	if !errors.As(err, &apiErr) {
		return
	}
	for name, value := range apiErr.ResponseHeaders {
		if strings.EqualFold(name, "Retry-After") || strings.EqualFold(name, "Retry-After-Ms") {
			header.Set(name, value)
		}
	}
}

func awaitLLMStreamSetup(ctx context.Context, events <-chan stream.Event) ([]stream.Event, error) {
	if events == nil {
		return nil, errors.New("LLM provider returned nil event stream")
	}
	var pending []stream.Event
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return pending, nil
			}
			if eventErr, ok := event.Data.(stream.ErrorEvent); ok {
				go drainLLMStream(ctx, events)
				return nil, eventErr.Error
			}
			pending = append(pending, event)
			if event.Type != stream.EventStart {
				return pending, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func drainLLMStream(ctx context.Context, events <-chan stream.Event) {
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// sanitizeEventData replaces empty json.RawMessage fields on stream
// events with null so encoding/json doesn't fail with "unexpected end
// of JSON input". Empty RawMessage shows up when a provider streams a
// tool-call frame before the input has been accumulated, or on partial
// reasoning/tool-call deltas.
func sanitizeEventData(data any) any {
	switch e := data.(type) {
	case stream.ToolCallEvent:
		e.Input = sanitizeRawMessage(e.Input)
		return e
	case stream.ToolResultEvent:
		e.Input = sanitizeRawMessage(e.Input)
		return e
	case stream.ToolErrorEvent:
		e.Input = sanitizeRawMessage(e.Input)
		return e
	case stream.ToolOutputDeniedEvent:
		e.Input = sanitizeRawMessage(e.Input)
		return e
	}
	return data
}

// sanitizeRawMessage normalizes a json.RawMessage to a value the JSON
// encoder accepts: empty (zero-length but non-nil) becomes null.
func sanitizeRawMessage(m json.RawMessage) json.RawMessage {
	if len(m) == 0 {
		return json.RawMessage("null")
	}
	return m
}

type ndJSONEvent struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// --- Non-language model handlers ---

// ImageGenerate handles POST /api/agent/llm/image.
func (h *Handler) ImageGenerate(w http.ResponseWriter, r *http.Request) {
	var req wire.ModelProxyRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().ImageGenerate(callbackContext(r), r.Header.Get("X-Airlock-Run-ID"), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Embed handles POST /api/agent/llm/embedding.
func (h *Handler) Embed(w http.ResponseWriter, r *http.Request) {
	var req wire.ModelProxyRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().Embed(callbackContext(r), r.Header.Get("X-Airlock-Run-ID"), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// SpeechGenerate handles POST /api/agent/llm/speech.
func (h *Handler) SpeechGenerate(w http.ResponseWriter, r *http.Request) {
	var req wire.ModelProxyRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().SpeechGenerate(callbackContext(r), r.Header.Get("X-Airlock-Run-ID"), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// Transcribe handles POST /api/agent/llm/transcription.
func (h *Handler) Transcribe(w http.ResponseWriter, r *http.Request) {
	var req wire.ModelProxyRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().Transcribe(callbackContext(r), r.Header.Get("X-Airlock-Run-ID"), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
