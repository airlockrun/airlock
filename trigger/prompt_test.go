package trigger

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/goai/model"
	"github.com/airlockrun/goai/testutil"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type recordingPromptDispatcher struct {
	mu     sync.Mutex
	inputs []wire.PromptInput
}

func (d *recordingPromptDispatcher) CancelRun(uuid.UUID) bool { return false }

func (d *recordingPromptDispatcher) ForwardPrompt(_ context.Context, _ uuid.UUID, input wire.PromptInput, _ *uuid.UUID, _ *uuid.UUID) (io.ReadCloser, uuid.UUID, error) {
	d.mu.Lock()
	d.inputs = append(d.inputs, input)
	d.mu.Unlock()
	return io.NopCloser(strings.NewReader("{\"type\":\"finish\",\"data\":{}}\n")), uuid.New(), nil
}

func (d *recordingPromptDispatcher) snapshot() []wire.PromptInput {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]wire.PromptInput(nil), d.inputs...)
}

type bridgeSuspensionFixture struct {
	agentID  uuid.UUID
	bridgeID uuid.UUID
	userID   uuid.UUID
	external string
	convID   uuid.UUID
	runID    uuid.UUID
}

func seedBridgeSuspension(t *testing.T) bridgeSuspensionFixture {
	t.Helper()
	ctx := context.Background()
	q := dbq.New(triggerTestDB.Pool())
	suffix := uuid.New().String()[:8]
	user, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email: "trigger-" + suffix + "@example.com", DisplayName: "Trigger User", TenantRole: "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	agent, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name: "trigger-" + suffix, Slug: "trigger-" + suffix, OwnerPrincipalID: user.ID, Config: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	bridgeID := uuid.New()
	if _, err := q.CreateBridge(ctx, dbq.CreateBridgeParams{
		ID: toPgUUID(bridgeID), Type: "telegram", Name: "bridge-" + suffix,
		AgentID: agent.ID, OwnerPrincipalID: user.ID,
	}); err != nil {
		t.Fatalf("CreateBridge: %v", err)
	}
	external := "chat-" + suffix
	conv, err := q.GetOrCreateBridgeAuthedConversation(ctx, dbq.GetOrCreateBridgeAuthedConversationParams{
		AgentID: agent.ID, UserID: user.ID, Title: "callback", BridgeID: toPgUUID(bridgeID),
		ExternalID: pgtype.Text{String: external, Valid: true},
	})
	if err != nil {
		t.Fatalf("GetOrCreateBridgeAuthedConversation: %v", err)
	}
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID: agent.ID, BridgeID: toPgUUID(bridgeID), InputPayload: []byte("{}"),
		TriggerType: "prompt", TriggerRef: uuid.UUID(conv.ID.Bytes).String(), CallerAccess: "user",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if _, err := triggerTestDB.Pool().Exec(ctx, "UPDATE runs SET status = 'suspended' WHERE id = $1", run.ID); err != nil {
		t.Fatalf("suspend run: %v", err)
	}
	return bridgeSuspensionFixture{
		agentID: uuid.UUID(agent.ID.Bytes), bridgeID: bridgeID, userID: uuid.UUID(user.ID.Bytes),
		external: external, convID: uuid.UUID(conv.ID.Bytes), runID: uuid.UUID(run.ID.Bytes),
	}
}

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

	t.Run("compaction lifecycle forwarded with typed fields", func(t *testing.T) {
		ndjson := `{"type":"compaction_started","data":{}}
{"type":"compaction_finished","data":{"tokensFreed":12,"error":"store failed"}}
`
		events := make(chan ResponseEvent, 16)
		_, _, _, err := StreamNDJSONResponse(strings.NewReader(ndjson), "run-compaction", events)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var received []ResponseEvent
		for event := range events {
			received = append(received, event)
		}
		if len(received) != 3 {
			t.Fatalf("received %d events, want 3", len(received))
		}
		if received[1].Type != "compaction_started" || received[1].RunID != "run-compaction" {
			t.Errorf("started = %+v", received[1])
		}
		finished := received[2]
		if finished.Type != "compaction_finished" || finished.RunID != "run-compaction" || finished.TokensFreed != 12 || finished.CompactionError != "store failed" {
			t.Errorf("finished = %+v", finished)
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

func TestHandleCallbackConcurrentDispatchesOnce(t *testing.T) {
	skipIfNoTriggerDB(t)
	for _, action := range []string{"approve", "deny"} {
		t.Run(action, func(t *testing.T) {
			fixture := seedBridgeSuspension(t)
			dispatcher := &recordingPromptDispatcher{}
			proxy := &PromptProxy{dispatcher: dispatcher, db: triggerTestDB, logger: zap.NewNop()}

			type result struct {
				stale bool
				err   error
			}
			results := make(chan result, 2)
			start := make(chan struct{})
			for range 2 {
				go func() {
					<-start
					events := make(chan ResponseEvent, 4)
					stale, err := proxy.HandleCallback(
						context.Background(), fixture.agentID, fixture.bridgeID, fixture.userID,
						fixture.external, action+":"+fixture.runID.String(), events,
					)
					results <- result{stale: stale, err: err}
				}()
			}
			close(start)

			staleCount := 0
			for range 2 {
				got := <-results
				if got.err != nil {
					t.Fatalf("HandleCallback: %v", got.err)
				}
				if got.stale {
					staleCount++
				}
			}
			if staleCount != 1 {
				t.Fatalf("stale callbacks = %d, want 1", staleCount)
			}
			inputs := dispatcher.snapshot()
			if len(inputs) != 1 {
				t.Fatalf("dispatched prompts = %d, want 1", len(inputs))
			}
			if inputs[0].ConversationID != fixture.convID.String() || inputs[0].ResumeRunID != fixture.runID.String() {
				t.Fatalf("dispatched input = %+v, want original conversation and run", inputs[0])
			}
			wantApproved := action == "approve"
			if inputs[0].Approved == nil || *inputs[0].Approved != wantApproved {
				t.Fatalf("Approved = %v, want %v", inputs[0].Approved, wantApproved)
			}
		})
	}
}

func TestHandleCallbackRequiresOriginalBridgeConversationIdentity(t *testing.T) {
	skipIfNoTriggerDB(t)

	tests := []struct {
		name   string
		mutate func(*testing.T, bridgeSuspensionFixture)
		call   func(bridgeSuspensionFixture) (uuid.UUID, uuid.UUID, uuid.UUID, string)
	}{
		{
			name: "agent",
			call: func(f bridgeSuspensionFixture) (uuid.UUID, uuid.UUID, uuid.UUID, string) {
				return uuid.New(), f.bridgeID, f.userID, f.external
			},
		},
		{
			name: "source",
			mutate: func(t *testing.T, f bridgeSuspensionFixture) {
				if _, err := triggerTestDB.Pool().Exec(context.Background(), "UPDATE agent_conversations SET source = 'web' WHERE id = $1", f.convID); err != nil {
					t.Fatalf("change conversation source: %v", err)
				}
			},
		},
		{
			name: "bridge",
			call: func(f bridgeSuspensionFixture) (uuid.UUID, uuid.UUID, uuid.UUID, string) {
				return f.agentID, uuid.New(), f.userID, f.external
			},
		},
		{
			name: "external id",
			call: func(f bridgeSuspensionFixture) (uuid.UUID, uuid.UUID, uuid.UUID, string) {
				return f.agentID, f.bridgeID, f.userID, "another-chat"
			},
		},
		{
			name: "user",
			call: func(f bridgeSuspensionFixture) (uuid.UUID, uuid.UUID, uuid.UUID, string) {
				return f.agentID, f.bridgeID, uuid.New(), f.external
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := seedBridgeSuspension(t)
			if tt.mutate != nil {
				tt.mutate(t, fixture)
			}
			var conversationsBefore int
			if err := triggerTestDB.Pool().QueryRow(context.Background(), "SELECT count(*) FROM agent_conversations").Scan(&conversationsBefore); err != nil {
				t.Fatalf("count conversations: %v", err)
			}
			agentID, bridgeID, userID, external := fixture.agentID, fixture.bridgeID, fixture.userID, fixture.external
			if tt.call != nil {
				agentID, bridgeID, userID, external = tt.call(fixture)
			}
			dispatcher := &recordingPromptDispatcher{}
			proxy := &PromptProxy{dispatcher: dispatcher, db: triggerTestDB, logger: zap.NewNop()}
			events := make(chan ResponseEvent, 4)
			stale, err := proxy.HandleCallback(context.Background(), agentID, bridgeID, userID, external, "deny:"+fixture.runID.String(), events)
			if err != nil {
				t.Fatalf("HandleCallback: %v", err)
			}
			if !stale {
				t.Fatal("HandleCallback accepted mismatched callback identity")
			}
			if got := len(dispatcher.snapshot()); got != 0 {
				t.Fatalf("dispatched prompts = %d, want 0", got)
			}
			var conversationsAfter int
			if err := triggerTestDB.Pool().QueryRow(context.Background(), "SELECT count(*) FROM agent_conversations").Scan(&conversationsAfter); err != nil {
				t.Fatalf("count conversations after callback: %v", err)
			}
			if conversationsAfter != conversationsBefore {
				t.Fatalf("conversation count = %d, want %d", conversationsAfter, conversationsBefore)
			}
			run, err := dbq.New(triggerTestDB.Pool()).GetRunByID(context.Background(), toPgUUID(fixture.runID))
			if err != nil {
				t.Fatalf("GetRunByID: %v", err)
			}
			if run.Status != "suspended" {
				t.Fatalf("run status = %q, want suspended", run.Status)
			}
		})
	}
}

func TestHandleMessageConcurrentAutoDenyResumesOnce(t *testing.T) {
	skipIfNoTriggerDB(t)
	fixture := seedBridgeSuspension(t)
	dispatcher := &recordingPromptDispatcher{}
	proxy := &PromptProxy{
		dispatcher: dispatcher,
		db:         triggerTestDB,
		agentBaseURL: func(slug string) string {
			return "https://" + slug + ".agents.example"
		},
		logger: zap.NewNop(),
	}

	errs := make(chan error, 2)
	start := make(chan struct{})
	for i := range 2 {
		go func(i int) {
			<-start
			events := make(chan ResponseEvent, 4)
			_, err := proxy.HandleMessage(
				context.Background(), fixture.agentID, fixture.bridgeID, fixture.userID,
				fixture.external, true, "message "+string(rune('a'+i)), nil, nil, events,
			)
			errs <- err
		}(i)
	}
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("HandleMessage: %v", err)
		}
	}

	inputs := dispatcher.snapshot()
	if len(inputs) != 2 {
		t.Fatalf("dispatched prompts = %d, want 2", len(inputs))
	}
	resumes := 0
	for _, input := range inputs {
		if input.ResumeRunID == "" {
			if input.Approved != nil {
				t.Fatalf("plain prompt has approval decision: %+v", input)
			}
			continue
		}
		resumes++
		if input.ResumeRunID != fixture.runID.String() || input.Approved == nil || *input.Approved {
			t.Fatalf("auto-deny input = %+v", input)
		}
	}
	if resumes != 1 {
		t.Fatalf("resume dispatches = %d, want 1", resumes)
	}
}
