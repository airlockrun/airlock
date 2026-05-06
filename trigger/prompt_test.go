package trigger

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/airlockrun/goai/model"
	"github.com/airlockrun/goai/testutil"
	"go.uber.org/zap"
)

func TestStreamNDJSONResponse(t *testing.T) {
	t.Run("text deltas collected and forwarded", func(t *testing.T) {
		ndjson := `{"type":"text-delta","data":{"text":"Hello "}}
{"type":"text-delta","data":{"text":"world"}}
{"type":"finish","data":{"usage":{"inputTokens":{"total":10},"outputTokens":{"total":5}}}}
`
		events := make(chan ResponseEvent, 16)
		text, _, usage, err := StreamNDJSONResponse(strings.NewReader(ndjson), "run-1", events)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if text != "Hello world" {
			t.Errorf("text = %q, want %q", text, "Hello world")
		}
		if usage == nil {
			t.Fatal("usage is nil")
		}
		if usage.PromptTokens != 10 {
			t.Errorf("promptTokens = %d, want 10", usage.PromptTokens)
		}
		if usage.CompletionTokens != 5 {
			t.Errorf("completionTokens = %d, want 5", usage.CompletionTokens)
		}

		// Verify events were forwarded (channel is closed by StreamNDJSONResponse).
		// First event is the run_started announcement.
		var received []ResponseEvent
		for ev := range events {
			received = append(received, ev)
		}
		if len(received) != 3 {
			t.Fatalf("received %d events, want 3", len(received))
		}
		if received[0].Type != "run_started" || received[0].RunID != "run-1" {
			t.Errorf("event[0] = %+v, want run_started for run-1", received[0])
		}
		if received[1].Type != "text-delta" || received[1].Text != "Hello " {
			t.Errorf("event[1] = %+v", received[1])
		}
		if received[2].Type != "text-delta" || received[2].Text != "world" {
			t.Errorf("event[2] = %+v", received[2])
		}
	})

	t.Run("error event with `error` key returns error", func(t *testing.T) {
		ndjson := `{"type":"text-delta","data":{"text":"partial"}}
{"type":"error","data":{"error":"model overloaded"}}
`
		events := make(chan ResponseEvent, 16)
		_, _, _, err := StreamNDJSONResponse(strings.NewReader(ndjson), "run-2", events)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "model overloaded") {
			t.Errorf("error = %v, want to contain 'model overloaded'", err)
		}
	})

	t.Run("error event with legacy `message` key still works", func(t *testing.T) {
		ndjson := `{"type":"error","data":{"message":"legacy msg"}}` + "\n"
		events := make(chan ResponseEvent, 16)
		_, _, _, err := StreamNDJSONResponse(strings.NewReader(ndjson), "run-2b", events)
		if err == nil || !strings.Contains(err.Error(), "legacy msg") {
			t.Fatalf("err = %v, want to contain 'legacy msg'", err)
		}
	})

	t.Run("confirmation_required forwarded with runID", func(t *testing.T) {
		ndjson := `{"type":"confirmation_required","data":{"permission":"run_js","patterns":["foo()"],"code":"foo()","toolCallId":"tc-1"}}
{"type":"finish","data":{}}
`
		events := make(chan ResponseEvent, 16)
		_, _, _, err := StreamNDJSONResponse(strings.NewReader(ndjson), "run-3", events)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var received []ResponseEvent
		for ev := range events {
			received = append(received, ev)
		}
		if len(received) != 2 {
			t.Fatalf("received %d events, want 2", len(received))
		}
		if received[0].Type != "run_started" || received[0].RunID != "run-3" {
			t.Errorf("event[0] = %+v, want run_started for run-3", received[0])
		}
		cr := received[1]
		if cr.Type != "confirmation_required" {
			t.Errorf("type = %q, want confirmation_required", cr.Type)
		}
		if cr.RunID != "run-3" {
			t.Errorf("RunID = %q, want run-3", cr.RunID)
		}
		if cr.Permission != "run_js" || cr.Code != "foo()" || cr.ToolCallID != "tc-1" {
			t.Errorf("confirmation fields = %+v", cr)
		}
	})

	t.Run("empty stream", func(t *testing.T) {
		events := make(chan ResponseEvent, 16)
		text, _, usage, err := StreamNDJSONResponse(strings.NewReader(""), "run-4", events)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if text != "" {
			t.Errorf("text = %q, want empty", text)
		}
		if usage != nil {
			t.Errorf("usage = %v, want nil", usage)
		}
	})
}

func TestTranscribeVoiceNotes(t *testing.T) {
	newProxy := func(resolver TranscriptionResolver) *PromptProxy {
		return &PromptProxy{
			logger:               zap.NewNop(),
			resolveTranscription: resolver,
		}
	}

	t.Run("appends tagged transcript and preserves original text", func(t *testing.T) {
		mock := testutil.NewMockTranscriptionModel(testutil.MockTranscriptionModelOptions{
			TranscribeResponse: &model.TranscriptionResult{Text: "hello there"},
		})
		p := newProxy(func(ctx context.Context) (model.TranscriptionModel, error) { return mock, nil })

		files := []BridgeFile{
			{Filename: "voice.ogg", ContentType: "audio/ogg", Data: []byte("audio-bytes"), IsVoiceNote: true},
		}
		keys := []string{"tmp/abc-voice.ogg"}
		got := p.transcribeVoiceNotes(context.Background(), "caption", files, keys)

		want := "caption\n[Voice note auto-transcript — source: \"tmp/abc-voice.ogg\"]\nhello there"
		if got != want {
			t.Errorf("userMessage = %q, want %q", got, want)
		}
		if len(mock.DoTranscribeCalls) != 1 {
			t.Fatalf("Transcribe calls = %d, want 1", len(mock.DoTranscribeCalls))
		}
		call := mock.DoTranscribeCalls[0]
		if string(call.Audio) != "audio-bytes" {
			t.Errorf("Audio bytes = %q, want audio-bytes", string(call.Audio))
		}
		if call.MimeType != "audio/ogg" {
			t.Errorf("MimeType = %q, want audio/ogg", call.MimeType)
		}
	})

	t.Run("returns tagged transcript when userMessage is empty", func(t *testing.T) {
		mock := testutil.NewMockTranscriptionModel(testutil.MockTranscriptionModelOptions{
			TranscribeResponse: &model.TranscriptionResult{Text: "just the transcript"},
		})
		p := newProxy(func(ctx context.Context) (model.TranscriptionModel, error) { return mock, nil })

		files := []BridgeFile{
			{Filename: "voice.ogg", ContentType: "audio/ogg", Data: []byte("x"), IsVoiceNote: true},
		}
		keys := []string{"tmp/xyz-voice.ogg"}
		got := p.transcribeVoiceNotes(context.Background(), "", files, keys)
		want := "[Voice note auto-transcript — source: \"tmp/xyz-voice.ogg\"]\njust the transcript"
		if got != want {
			t.Errorf("userMessage = %q, want %q", got, want)
		}
	})

	t.Run("skips non-voice files", func(t *testing.T) {
		calls := 0
		mock := testutil.NewMockTranscriptionModel(testutil.MockTranscriptionModelOptions{
			DoTranscribeFunc: func(ctx context.Context, opts model.TranscribeCallOptions) (*model.TranscriptionResult, error) {
				calls++
				return &model.TranscriptionResult{Text: "x"}, nil
			},
		})
		resolverCalls := 0
		p := newProxy(func(ctx context.Context) (model.TranscriptionModel, error) {
			resolverCalls++
			return mock, nil
		})

		files := []BridgeFile{
			{Filename: "photo.jpg", ContentType: "image/jpeg", Data: []byte("img")},
			{Filename: "doc.pdf", ContentType: "application/pdf", Data: []byte("pdf")},
		}
		keys := []string{"tmp/photo.jpg", "tmp/doc.pdf"}
		got := p.transcribeVoiceNotes(context.Background(), "caption", files, keys)
		if got != "caption" {
			t.Errorf("userMessage = %q, want %q", got, "caption")
		}
		if calls != 0 {
			t.Errorf("Transcribe called %d times, want 0", calls)
		}
		if resolverCalls != 0 {
			t.Errorf("resolver called %d times, want 0 when no voice notes present", resolverCalls)
		}
	})

	t.Run("degrades silently when transcription not configured", func(t *testing.T) {
		p := newProxy(func(ctx context.Context) (model.TranscriptionModel, error) {
			return nil, ErrTranscriptionNotConfigured
		})

		files := []BridgeFile{
			{Filename: "voice.ogg", ContentType: "audio/ogg", Data: []byte("x"), IsVoiceNote: true},
		}
		keys := []string{"tmp/v.ogg"}
		got := p.transcribeVoiceNotes(context.Background(), "caption", files, keys)
		if got != "caption" {
			t.Errorf("userMessage = %q, want caption (unchanged)", got)
		}
	})

	t.Run("degrades when resolver fails for other reasons", func(t *testing.T) {
		p := newProxy(func(ctx context.Context) (model.TranscriptionModel, error) {
			return nil, errors.New("provider down")
		})

		files := []BridgeFile{
			{Filename: "voice.ogg", ContentType: "audio/ogg", Data: []byte("x"), IsVoiceNote: true},
		}
		keys := []string{"tmp/v.ogg"}
		got := p.transcribeVoiceNotes(context.Background(), "caption", files, keys)
		if got != "caption" {
			t.Errorf("userMessage = %q, want caption (unchanged)", got)
		}
	})

	t.Run("degrades when Transcribe call fails", func(t *testing.T) {
		mock := testutil.NewMockTranscriptionModel(testutil.MockTranscriptionModelOptions{
			DoTranscribeFunc: func(ctx context.Context, opts model.TranscribeCallOptions) (*model.TranscriptionResult, error) {
				return nil, errors.New("429 rate limit")
			},
		})
		p := newProxy(func(ctx context.Context) (model.TranscriptionModel, error) { return mock, nil })

		files := []BridgeFile{
			{Filename: "voice.ogg", ContentType: "audio/ogg", Data: []byte("x"), IsVoiceNote: true},
		}
		keys := []string{"tmp/v.ogg"}
		got := p.transcribeVoiceNotes(context.Background(), "caption", files, keys)
		if got != "caption" {
			t.Errorf("userMessage = %q, want caption (unchanged)", got)
		}
	})

	t.Run("no-op when resolver is nil", func(t *testing.T) {
		p := newProxy(nil)

		files := []BridgeFile{
			{Filename: "voice.ogg", ContentType: "audio/ogg", Data: []byte("x"), IsVoiceNote: true},
		}
		keys := []string{"tmp/v.ogg"}
		got := p.transcribeVoiceNotes(context.Background(), "hi", files, keys)
		if got != "hi" {
			t.Errorf("userMessage = %q, want hi", got)
		}
	})
}
