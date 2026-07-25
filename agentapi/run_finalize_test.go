package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/goai/message"
	"github.com/airlockrun/sol/session"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestNormalizeToolOrderingPreservesValidHistory(t *testing.T) {
	convID := toPgUUID(uuid.New())
	msgs := []dbq.AgentMessage{
		{ConversationID: convID, Role: "user", Content: "start", Seq: 1},
		{ConversationID: convID, Role: "assistant", Parts: []byte(`[
			{"type":"tool-call","toolCallId":"call-a","toolName":"first","args":{}},
			{"type":"tool-call","toolCallId":"call-b","toolName":"second","args":{}}
		]`), Seq: 2},
		{ConversationID: convID, Role: "tool", Parts: []byte(`[{
			"type":"tool-result","toolCallId":"call-a","toolName":"first","output":{"type":"text","value":"a"}
		}]`), Seq: 3},
		{ConversationID: convID, Role: "tool", Parts: []byte(`[{
			"type":"tool-result","toolCallId":"call-b","toolName":"second","output":{"type":"text","value":"b"}
		}]`), Seq: 4},
		{ConversationID: convID, Role: "assistant", Content: "done", Seq: 5},
	}

	got, dangling, missing, err := normalizeToolOrdering(convID, msgs)
	if err != nil {
		t.Fatalf("normalizeToolOrdering: %v", err)
	}
	if !reflect.DeepEqual(got, msgs) {
		t.Fatalf("valid history changed:\n got: %#v\nwant: %#v", got, msgs)
	}
	if len(dangling) != 0 || len(missing) != 0 {
		t.Fatalf("repairs for valid history: dangling=%v missing=%v", dangling, missing)
	}
}

func TestNormalizeToolOrderingCanonicalizesLegacySyntheticResult(t *testing.T) {
	convID := toPgUUID(uuid.New())
	msgs := []dbq.AgentMessage{
		{ConversationID: convID, Role: "assistant", Parts: []byte(`[{"type":"tool-call","toolCallId":"call-a","toolName":"lookup","args":{}}]`)},
		{
			ConversationID: convID,
			Role:           "tool",
			Content:        "Tool timed out.",
			Source:         "synthetic",
			Parts:          []byte(`[{"type":"tool-result","toolCallId":"call-a","toolName":"lookup","result":"Tool timed out.","isError":true}]`),
		},
	}

	got, dangling, missing, err := normalizeToolOrdering(convID, msgs)
	if err != nil {
		t.Fatalf("normalizeToolOrdering: %v", err)
	}
	if len(dangling) != 0 || len(missing) != 0 {
		t.Fatalf("repairs: dangling=%v missing=%v", dangling, missing)
	}
	if reflect.DeepEqual(got, msgs) {
		t.Fatal("result-field history returned unchanged")
	}
	if got[1].Content != "Tool timed out." || got[1].Source != "synthetic" {
		t.Fatalf("tool row metadata changed: content=%q source=%q", got[1].Content, got[1].Source)
	}
	var rawParts []map[string]json.RawMessage
	if err := json.Unmarshal(got[1].Parts, &rawParts); err != nil {
		t.Fatalf("decode normalized parts: %v", err)
	}
	if _, ok := rawParts[0]["result"]; ok {
		t.Fatalf("normalized part retained result: %s", got[1].Parts)
	}
	if _, ok := rawParts[0]["output"]; !ok {
		t.Fatalf("normalized part has no output: %s", got[1].Parts)
	}

	sessionMessages := []session.Message{dbMessageToSession(got[0]), dbMessageToSession(got[1])}
	history := session.MessagesToGoAI(sessionMessages)
	if len(history) != 2 || history[1].Role != message.RoleTool {
		t.Fatalf("provider history = %#v, want assistant then tool", history)
	}
	result, ok := history[1].Content.Parts[0].(message.ToolResultPart)
	if !ok || result.ToolCallID != "call-a" {
		t.Fatalf("provider result = %#v, want matching call-a result", history[1].Content.Parts)
	}
	output, ok := result.Output.(message.ErrorTextOutput)
	if !ok || output.Value != "Tool timed out." {
		t.Fatalf("provider output = %#v, want error-text timeout", result.Output)
	}
}

func TestNormalizeToolOrderingCanonicalizesLegacyResultWithExtras(t *testing.T) {
	convID := toPgUUID(uuid.New())
	msgs := []dbq.AgentMessage{
		{ConversationID: convID, Role: "assistant", Parts: []byte(`[{"type":"tool-call","toolCallId":"call-a","toolName":"lookup","args":{}}]`)},
		{
			ConversationID: convID,
			Role:           "tool",
			Content:        "stored display text",
			Source:         "synthetic",
			Parts: []byte(`[
				{"type":"tool-result","toolCallId":"call-a","toolName":"lookup","result":"found","providerOptions":{"trace":"kept"}},
				{"type":"text","text":"diagnostic"},
				{"type":"file","data":{"type":"text","text":"attachment"},"mimeType":"text/plain","filename":"diag.txt"}
			]`),
		},
	}

	got, _, _, err := normalizeToolOrdering(convID, msgs)
	if err != nil {
		t.Fatalf("normalizeToolOrdering: %v", err)
	}
	if got[1].Content != "stored display text" || got[1].Source != "synthetic" {
		t.Fatalf("tool row metadata changed: content=%q source=%q", got[1].Content, got[1].Source)
	}
	var normalized []map[string]json.RawMessage
	if err := json.Unmarshal(got[1].Parts, &normalized); err != nil {
		t.Fatalf("decode normalized parts: %v", err)
	}
	if len(normalized) != 3 {
		t.Fatalf("normalized parts = %d, want result and two extras", len(normalized))
	}
	if _, ok := normalized[0]["providerOptions"]; !ok {
		t.Fatalf("tool-result fields were not preserved: %s", got[1].Parts)
	}

	history := session.MessagesToGoAI([]session.Message{dbMessageToSession(got[0]), dbMessageToSession(got[1])})
	if len(history) != 2 {
		t.Fatalf("provider history = %#v, want two messages", history)
	}
	result, ok := history[1].Content.Parts[0].(message.ToolResultPart)
	if !ok {
		t.Fatalf("provider result = %T, want ToolResultPart", history[1].Content.Parts[0])
	}
	output, ok := result.Output.(message.TextOutput)
	if !ok || output.Value != "found" {
		t.Fatalf("provider output = %#v, want text found", result.Output)
	}
	if len(history[1].Content.Parts) != 3 {
		t.Fatalf("provider tool parts = %#v, want result and two extras", history[1].Content.Parts)
	}
	if text, ok := history[1].Content.Parts[1].(message.TextPart); !ok || text.Text != "diagnostic" {
		t.Fatalf("provider text extra = %#v", history[1].Content.Parts[1])
	}
	if file, ok := history[1].Content.Parts[2].(message.FilePart); !ok || file.Filename != "diag.txt" {
		t.Fatalf("provider file extra = %#v", history[1].Content.Parts[2])
	}
}

func TestNormalizeToolOrderingMovesLateResultsAndFillsPartialTurn(t *testing.T) {
	convID := toPgUUID(uuid.New())
	msgs := []dbq.AgentMessage{
		{ConversationID: convID, Role: "assistant", Parts: []byte(`[
			{"type":"tool-call","toolCallId":"call-a","toolName":"first","args":{}},
			{"type":"tool-call","toolCallId":"call-b","toolName":"second","args":{}},
			{"type":"tool-call","toolCallId":"call-c","toolName":"third","args":{}}
		]`)},
		{ConversationID: convID, Role: "tool", Source: "real-a", Parts: []byte(`[{
			"type":"tool-result","toolCallId":"call-a","toolName":"first","output":{"type":"text","value":"a"}
		}]`)},
		{ConversationID: convID, Role: "assistant", Content: "must follow results"},
		{ConversationID: convID, Role: "tool", Source: "real-b", Parts: []byte(`[{
			"type":"tool-result","toolCallId":"call-b","toolName":"second","output":{"type":"text","value":"b"}
		}]`)},
		{ConversationID: convID, Role: "user", Content: "later user turn"},
	}

	got, dangling, missing, err := normalizeToolOrdering(convID, msgs)
	if err != nil {
		t.Fatalf("normalizeToolOrdering: %v", err)
	}
	if len(dangling) != 0 {
		t.Fatalf("dangling repairs = %v, want none", dangling)
	}
	if !reflect.DeepEqual(missing, []orphanPair{{ToolCallID: "call-c", ToolName: "third"}}) {
		t.Fatalf("missing repairs = %v", missing)
	}
	wantRoles := []string{"assistant", "tool", "tool", "tool", "assistant", "user"}
	if len(got) != len(wantRoles) {
		t.Fatalf("messages = %d, want %d: %#v", len(got), len(wantRoles), got)
	}
	for i, role := range wantRoles {
		if got[i].Role != role {
			t.Fatalf("message %d role = %q, want %q", i, got[i].Role, role)
		}
	}
	for i, wantID := range []string{"call-a", "call-b", "call-c"} {
		parts, ok := parseToolParts(got[i+1].Parts, "tool-result")
		if !ok || len(parts) != 1 || parts[0].Pair.ToolCallID != wantID {
			t.Fatalf("result %d = %#v, want %q", i, parts, wantID)
		}
	}
	if got[2].Source != "real-b" {
		t.Fatalf("late real result source = %q, want real-b", got[2].Source)
	}
	if got[3].Source != "synthetic" {
		t.Fatalf("missing result source = %q, want synthetic", got[3].Source)
	}
	if valid, err := toolOrderingValid(got); err != nil || !valid {
		t.Fatal("normalized history is not provider-valid")
	}
}

func TestNormalizeToolOrderingPairsDanglingResults(t *testing.T) {
	convID := toPgUUID(uuid.New())
	msgs := []dbq.AgentMessage{
		{ConversationID: convID, Role: "user", Content: "before"},
		{ConversationID: convID, Role: "tool", Source: "real", Parts: []byte(`[
			{"type":"tool-result","toolCallId":"call-x","toolName":"orphan","output":{"type":"text","value":"x"}},
			{"type":"tool-result","toolCallId":"call-y","toolName":"orphan","output":{"type":"text","value":"y"}}
		]`)},
		{ConversationID: convID, Role: "assistant", Content: "after"},
	}

	got, dangling, missing, err := normalizeToolOrdering(convID, msgs)
	if err != nil {
		t.Fatalf("normalizeToolOrdering: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("missing repairs = %v, want none", missing)
	}
	if len(dangling) != 2 || dangling[0].ToolCallID != "call-x" || dangling[1].ToolCallID != "call-y" {
		t.Fatalf("dangling repairs = %v", dangling)
	}
	wantRoles := []string{"user", "assistant", "tool", "tool", "assistant"}
	for i, role := range wantRoles {
		if got[i].Role != role {
			t.Fatalf("message %d role = %q, want %q", i, got[i].Role, role)
		}
	}
	if valid, err := toolOrderingValid(got); err != nil || !valid {
		t.Fatal("dangling result repair is not provider-valid")
	}
}

func TestNormalizeToolOrderingRestoresAssistantCallOrder(t *testing.T) {
	convID := toPgUUID(uuid.New())
	msgs := []dbq.AgentMessage{
		{ConversationID: convID, Role: "assistant", Parts: []byte(`[
			{"type":"tool-call","toolCallId":"call-a","toolName":"first","args":{}},
			{"type":"tool-call","toolCallId":"call-b","toolName":"second","args":{}}
		]`)},
		{ConversationID: convID, Role: "tool", Parts: []byte(`[{"type":"tool-result","toolCallId":"call-b","toolName":"second","output":{"type":"text","value":"b"}}]`)},
		{ConversationID: convID, Role: "tool", Parts: []byte(`[{"type":"tool-result","toolCallId":"call-a","toolName":"first","output":{"type":"text","value":"a"}}]`)},
	}

	valid, err := toolOrderingValid(msgs)
	if err != nil {
		t.Fatalf("toolOrderingValid: %v", err)
	}
	if valid {
		t.Fatal("reversed results were accepted")
	}
	got, _, _, err := normalizeToolOrdering(convID, msgs)
	if err != nil {
		t.Fatalf("normalizeToolOrdering: %v", err)
	}
	for i, wantID := range []string{"call-a", "call-b"} {
		parts, _ := parseToolParts(got[i+1].Parts, "tool-result")
		if len(parts) != 1 || parts[0].Pair.ToolCallID != wantID {
			t.Fatalf("result %d = %#v, want %q", i, parts, wantID)
		}
	}
}

func TestNormalizeToolOrderingPreservesToolRowExtras(t *testing.T) {
	convID := toPgUUID(uuid.New())
	msgs := []dbq.AgentMessage{
		{ConversationID: convID, Role: "assistant", Parts: []byte(`[
			{"type":"tool-call","toolCallId":"call-a","toolName":"first","args":{}},
			{"type":"tool-call","toolCallId":"call-b","toolName":"second","args":{}}
		]`)},
		{ConversationID: convID, Role: "tool", Parts: []byte(`[
			{"type":"tool-result","toolCallId":"call-b","toolName":"second","output":{"type":"text","value":"b"}},
			{"type":"text","text":"diagnostic"},
			{"type":"file","data":{"type":"text","text":"attachment"},"mimeType":"text/plain","filename":"diag.txt"}
		]`)},
		{ConversationID: convID, Role: "assistant", Content: "late"},
		{ConversationID: convID, Role: "tool", Parts: []byte(`[{"type":"tool-result","toolCallId":"call-a","toolName":"first","output":{"type":"text","value":"a"}}]`)},
	}

	got, _, _, err := normalizeToolOrdering(convID, msgs)
	if err != nil {
		t.Fatalf("normalizeToolOrdering: %v", err)
	}
	var sessionMessages []session.Message
	for _, msg := range got {
		sessionMessages = append(sessionMessages, dbMessageToSession(msg))
	}
	history := session.MessagesToGoAI(sessionMessages)
	var foundText, foundFile bool
	for _, msg := range history {
		for _, part := range msg.Content.Parts {
			switch part := part.(type) {
			case message.TextPart:
				foundText = foundText || part.Text == "diagnostic"
			case message.FilePart:
				foundFile = foundFile || part.Filename == "diag.txt"
			}
		}
	}
	if !foundText || !foundFile {
		t.Fatalf("provider history lost tool row extras: text=%v file=%v", foundText, foundFile)
	}
}

func TestNormalizeToolOrderingRejectsMalformedToolRow(t *testing.T) {
	convID := toPgUUID(uuid.New())
	msgs := []dbq.AgentMessage{{
		ConversationID: convID,
		Role:           "tool",
		Content:        "diagnostic content",
		Parts:          []byte(`[{"type":"unknown","value":"do not drop"}]`),
	}}
	if _, _, _, err := normalizeToolOrdering(convID, msgs); err == nil {
		t.Fatal("normalizeToolOrdering accepted an unrecognized tool row")
	}
}

func TestNormalizeToolOrderingRejectsMalformedLegacyResult(t *testing.T) {
	convID := toPgUUID(uuid.New())
	for _, tt := range []struct {
		name  string
		parts string
	}{
		{
			name:  "structured result",
			parts: `[{"type":"tool-result","toolCallId":"call-a","toolName":"lookup","result":{"value":"not the persisted string shape"}}]`,
		},
		{
			name:  "non-boolean error flag",
			parts: `[{"type":"tool-result","toolCallId":"call-a","toolName":"lookup","result":"failed","isError":"true"}]`,
		},
		{
			name:  "ambiguous output and result",
			parts: `[{"type":"tool-result","toolCallId":"call-a","toolName":"lookup","result":"old","output":{"type":"text","value":"new"}}]`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			msgs := []dbq.AgentMessage{
				{ConversationID: convID, Role: "assistant", Parts: []byte(`[{"type":"tool-call","toolCallId":"call-a","toolName":"lookup","args":{}}]`)},
				{ConversationID: convID, Role: "tool", Parts: []byte(tt.parts)},
			}
			if _, _, _, err := normalizeToolOrdering(convID, msgs); err == nil {
				t.Fatal("normalizeToolOrdering accepted malformed result-field output")
			}
		})
	}
}

func TestSynthesizeOrphanToolResultsReachesProviderHistory(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)
	q := dbq.New(testDB.Pool())
	ctx := context.Background()
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID:      toPgUUID(agentID),
		InputPayload: []byte(`{}`),
		SourceRef:    "",
		TriggerType:  "prompt",
		TriggerRef:   convID.String(),
		CallerAccess: "user",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if _, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
		ConversationID: toPgUUID(convID),
		Role:           "assistant",
		Parts:          []byte(`[{"type":"tool-call","toolCallId":"call-a","toolName":"lookup","args":{}}]`),
		RunID:          run.ID,
	}); err != nil {
		t.Fatalf("CreateMessage: %v", err)
	}

	SynthesizeOrphanToolResults(ctx, q, pgUUID(run.ID), "timeout", testAgentHandler().logger)
	dbMessages, err := q.ListSessionMessagesByConversation(ctx, toPgUUID(convID))
	if err != nil {
		t.Fatalf("ListSessionMessagesByConversation: %v", err)
	}
	dbMessages, _, _, err = normalizeToolOrdering(toPgUUID(convID), dbMessages)
	if err != nil {
		t.Fatalf("normalizeToolOrdering: %v", err)
	}
	var sessionMessages []session.Message
	for _, msg := range dbMessages {
		sessionMessages = append(sessionMessages, dbMessageToSession(msg))
	}
	history := session.MessagesToGoAI(sessionMessages)
	if len(history) != 2 || history[1].Role != message.RoleTool {
		t.Fatalf("provider history = %#v, want assistant then tool", history)
	}
	result, ok := history[1].Content.Parts[0].(message.ToolResultPart)
	if !ok {
		t.Fatalf("provider result = %T, want ToolResultPart", history[1].Content.Parts[0])
	}
	output, ok := result.Output.(message.ErrorTextOutput)
	if !ok || output.Value != "Tool timed out." {
		t.Fatalf("provider output = %#v, want error-text timeout", result.Output)
	}
}

func TestSessionLoadFailsOnMalformedToolRow(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)
	if _, err := dbq.New(testDB.Pool()).CreateMessage(context.Background(), dbq.CreateMessageParams{
		ConversationID: toPgUUID(convID),
		Role:           "tool",
		Content:        "diagnostic content",
		Parts:          []byte(`[{"type":"unknown","value":"do not drop"}]`),
	}); err != nil {
		t.Fatalf("CreateMessage: %v", err)
	}
	router := testRouter(ah, func(r chi.Router) {
		r.Get("/api/agent/session/{convID}/messages", ah.SessionLoad)
	})
	req := agentRequest(t, http.MethodGet, "/api/agent/session/"+convID.String()+"/messages", agentID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
}

func TestValidateSuspendedCheckpoint(t *testing.T) {
	for _, tt := range []struct {
		name       string
		checkpoint string
		valid      bool
	}{
		{name: "permission", checkpoint: `{"suspensionContext":{"reason":"permission"}}`, valid: true},
		{name: "delegated", checkpoint: `{"suspensionContext":{"reason":"delegated"}}`, valid: true},
		{name: "missing"},
		{name: "malformed", checkpoint: `{`},
		{name: "empty object", checkpoint: `{}`},
		{name: "array", checkpoint: `[]`},
		{name: "scalar", checkpoint: `"checkpoint"`},
		{name: "null context", checkpoint: `{"suspensionContext":null}`},
		{name: "empty reason", checkpoint: `{"suspensionContext":{"reason":""}}`},
		{name: "unsupported reason", checkpoint: `{"suspensionContext":{"reason":"confirmation"}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSuspendedCheckpoint([]byte(tt.checkpoint))
			if (err == nil) != tt.valid {
				t.Fatalf("ValidateSuspendedCheckpoint() error = %v, valid = %v", err, tt.valid)
			}
		})
	}
}

func TestRunCompleteSuspendedRequiresAndAtomicallyStoresCheckpoint(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID := createTestAgent(t)
	router := testRouter(ah, func(r chi.Router) {
		r.Post("/api/agent/run/complete", ah.RunComplete)
	})
	q := dbq.New(testDB.Pool())

	createRun := func(t *testing.T) dbq.Run {
		t.Helper()
		run, err := q.CreateRun(context.Background(), dbq.CreateRunParams{
			AgentID:      toPgUUID(agentID),
			InputPayload: []byte(`{}`),
			SourceRef:    "",
			TriggerType:  "prompt",
			TriggerRef:   uuid.NewString(),
			CallerAccess: "user",
		})
		if err != nil {
			t.Fatalf("CreateRun: %v", err)
		}
		return run
	}

	for _, tt := range []struct {
		name       string
		checkpoint json.RawMessage
	}{
		{name: "missing checkpoint"},
		{name: "null checkpoint", checkpoint: json.RawMessage(`null`)},
		{name: "empty object", checkpoint: json.RawMessage(`{}`)},
		{name: "array", checkpoint: json.RawMessage(`[]`)},
		{name: "scalar", checkpoint: json.RawMessage(`"checkpoint"`)},
		{name: "null suspension context", checkpoint: json.RawMessage(`{"suspensionContext":null}`)},
		{name: "empty reason", checkpoint: json.RawMessage(`{"suspensionContext":{"reason":""}}`)},
		{name: "unsupported reason", checkpoint: json.RawMessage(`{"suspensionContext":{"reason":"confirmation"}}`)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			run := createRun(t)
			req := agentRequest(t, http.MethodPost, "/api/agent/run/complete", agentID, wire.RunCompleteRequest{
				RunID: runID(run), Status: "suspended", Checkpoint: tt.checkpoint,
			})
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
			stored, err := q.GetRunByID(context.Background(), run.ID)
			if err != nil {
				t.Fatalf("GetRunByID: %v", err)
			}
			if stored.Status != "running" || len(stored.Checkpoint) != 0 {
				t.Fatalf("stored run = status %q checkpoint %s", stored.Status, stored.Checkpoint)
			}
		})
	}

	t.Run("status and checkpoint", func(t *testing.T) {
		run := createRun(t)
		checkpoint := json.RawMessage(`{"messages":[],"suspensionContext":{"reason":"permission"}}`)
		req := agentRequest(t, http.MethodPost, "/api/agent/run/complete", agentID, wire.RunCompleteRequest{
			RunID: runID(run), Status: "suspended", Checkpoint: checkpoint,
		})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		stored, err := q.GetRunByID(context.Background(), run.ID)
		if err != nil {
			t.Fatalf("GetRunByID: %v", err)
		}
		if stored.Status != "suspended" {
			t.Fatalf("status = %q, want suspended", stored.Status)
		}
		var gotCheckpoint, wantCheckpoint any
		if err := json.Unmarshal(stored.Checkpoint, &gotCheckpoint); err != nil {
			t.Fatalf("decode stored checkpoint: %v", err)
		}
		if err := json.Unmarshal(checkpoint, &wantCheckpoint); err != nil {
			t.Fatalf("decode expected checkpoint: %v", err)
		}
		if !reflect.DeepEqual(gotCheckpoint, wantCheckpoint) {
			t.Fatalf("checkpoint = %s, want %s", stored.Checkpoint, checkpoint)
		}
	})
}

func TestRunCompleteIsMonotonicAndDuplicateIsIdempotent(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID, userID := testAgentAndUser(t)
	convID := testConversation(t, agentID, userID)
	router := testRouter(ah, func(r chi.Router) {
		r.Post("/api/agent/run/complete", ah.RunComplete)
	})
	q := dbq.New(testDB.Pool())
	ctx := context.Background()
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID:      toPgUUID(agentID),
		InputPayload: []byte(`{}`),
		SourceRef:    "",
		TriggerType:  "prompt",
		TriggerRef:   convID.String(),
		CallerAccess: "user",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if _, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
		ConversationID: toPgUUID(convID),
		Role:           "assistant",
		Parts:          []byte(`[{"type":"tool-call","toolCallId":"call-a","toolName":"lookup","args":{}}]`),
		RunID:          run.ID,
	}); err != nil {
		t.Fatalf("CreateMessage: %v", err)
	}
	completion := wire.RunCompleteRequest{RunID: runID(run), Status: "error", Error: "failed"}
	complete := func(body wire.RunCompleteRequest) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, agentRequest(t, http.MethodPost, "/api/agent/run/complete", agentID, body))
		return rec
	}
	if rec := complete(completion); rec.Code != http.StatusOK {
		t.Fatalf("first completion status = %d; body: %s", rec.Code, rec.Body.String())
	}
	if rec := complete(completion); rec.Code != http.StatusOK {
		t.Fatalf("duplicate completion status = %d; body: %s", rec.Code, rec.Body.String())
	}
	messages, err := q.ListAllMessagesByConversation(ctx, toPgUUID(convID))
	if err != nil {
		t.Fatalf("ListAllMessagesByConversation: %v", err)
	}
	if len(messages) != 3 {
		t.Fatalf("messages = %d, want tool-call, synthetic result, and one error", len(messages))
	}
	if messages[0].Role != "assistant" || messages[1].Role != "tool" || messages[1].Source != "synthetic" || messages[2].Source != "error" {
		t.Fatalf("message order = %#v", messages)
	}

	delayed := completion
	delayed.Status = "success"
	delayed.Error = ""
	if rec := complete(delayed); rec.Code != http.StatusConflict {
		t.Fatalf("different terminal completion status = %d, want 409; body: %s", rec.Code, rec.Body.String())
	}
	stored, err := q.GetRunByID(ctx, run.ID)
	if err != nil {
		t.Fatalf("GetRunByID: %v", err)
	}
	if stored.Status != "error" || stored.ErrorMessage != "failed" {
		t.Fatalf("stored completion = status %q error %q", stored.Status, stored.ErrorMessage)
	}
}

func TestRunCompleteDoesNotOverwriteTerminalStates(t *testing.T) {
	skipIfNoDB(t)
	ah := testAgentHandler()
	agentID := createTestAgent(t)
	router := testRouter(ah, func(r chi.Router) {
		r.Post("/api/agent/run/complete", ah.RunComplete)
	})
	q := dbq.New(testDB.Pool())
	ctx := context.Background()
	for _, tt := range []struct {
		existing string
		incoming wire.RunCompleteRequest
	}{
		{existing: "cancelled", incoming: wire.RunCompleteRequest{Status: "success"}},
		{existing: "timeout", incoming: wire.RunCompleteRequest{Status: "suspended", Checkpoint: json.RawMessage(`{"suspensionContext":{"reason":"permission"}}`)}},
		{existing: "success", incoming: wire.RunCompleteRequest{Status: "error", Error: "late error"}},
	} {
		t.Run(tt.existing+"_then_"+tt.incoming.Status, func(t *testing.T) {
			run, err := q.CreateRun(ctx, dbq.CreateRunParams{
				AgentID: toPgUUID(agentID), InputPayload: []byte(`{}`), SourceRef: "",
				TriggerType: "prompt", TriggerRef: uuid.NewString(), CallerAccess: "user",
			})
			if err != nil {
				t.Fatalf("CreateRun: %v", err)
			}
			if err := q.UpdateRunComplete(ctx, dbq.UpdateRunCompleteParams{ID: run.ID, Status: tt.existing, Actions: []byte(`[]`)}); err != nil {
				t.Fatalf("UpdateRunComplete: %v", err)
			}
			tt.incoming.RunID = runID(run)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, agentRequest(t, http.MethodPost, "/api/agent/run/complete", agentID, tt.incoming))
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body: %s", rec.Code, rec.Body.String())
			}
			stored, err := q.GetRunByID(ctx, run.ID)
			if err != nil {
				t.Fatalf("GetRunByID: %v", err)
			}
			if stored.Status != tt.existing {
				t.Fatalf("stored status = %q, want %q", stored.Status, tt.existing)
			}
		})
	}
}

func runID(run dbq.Run) string {
	return uuid.UUID(run.ID.Bytes).String()
}
