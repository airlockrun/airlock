package sysagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/goai"
	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/goai/testutil"
	"github.com/airlockrun/goai/tool"
	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/agent"
	"github.com/airlockrun/sol/bus"
	"github.com/airlockrun/sol/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// isDoomLoopSuspension recognises the doom-loop suspension after the
// SuspensionContext round-trips through JSON (which is the shape the
// resume path actually sees).
func TestIsDoomLoopSuspension(t *testing.T) {
	cases := []struct {
		name string
		sc   sol.SuspensionContext
		want bool
	}{
		{
			name: "doom_loop permission — match",
			sc: sol.SuspensionContext{
				Reason: "permission",
				Data:   &bus.ErrPermissionNeeded{Permission: "doom_loop", Patterns: []string{"list_runs"}},
			},
			want: true,
		},
		{
			name: "other permission — no match",
			sc: sol.SuspensionContext{
				Reason: "permission",
				Data:   &bus.ErrPermissionNeeded{Permission: "edit", Patterns: []string{"/x"}},
			},
			want: false,
		},
		{
			name: "question reason — no match",
			sc:   sol.SuspensionContext{Reason: "question"},
			want: false,
		},
		{
			name: "delegated reason — no match",
			sc:   sol.SuspensionContext{Reason: "delegated"},
			want: false,
		},
		{
			name: "empty — no match",
			sc:   sol.SuspensionContext{},
			want: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Round-trip through JSON to match what dispatchResume sees
			// (Data is `any`; after unmarshal it lands as map[string]any).
			raw, err := json.Marshal(tt.sc)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got sol.SuspensionContext
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if isDoomLoopSuspension(got) != tt.want {
				t.Errorf("isDoomLoopSuspension(...) = %v, want %v", !tt.want, tt.want)
			}
		})
	}
}

func TestDispatchResumeRequiresSeparateApprovals(t *testing.T) {
	calls := []stream.ToolCall{
		{ID: "gated-a", Name: "gated_a", Input: json.RawMessage(`{"n":1}`)},
		{ID: "safe", Name: "safe", Input: json.RawMessage(`{"n":2}`)},
		{ID: "gated-b", Name: "gated_b", Input: json.RawMessage(`{"n":3}`)},
		{ID: "tail", Name: "tail", Input: json.RawMessage(`{"n":4}`)},
	}
	var effects, order []string
	tools := permissionResumeTools(&effects)
	store := &permissionResumeStore{
		messages: []session.Message{session.FromGoAIMessage(goai.NewAssistantMessageWithParts(
			goai.ToolCallPart{ID: calls[0].ID, Name: calls[0].Name, Input: calls[0].Input},
			goai.ToolCallPart{ID: calls[1].ID, Name: calls[1].Name, Input: calls[1].Input},
			goai.ToolCallPart{ID: calls[2].ID, Name: calls[2].Name, Input: calls[2].Input},
			goai.ToolCallPart{ID: calls[3].ID, Name: calls[3].Name, Input: calls[3].Input},
		))},
		order: &order,
	}
	model := testutil.NewMockLanguageModel(testutil.MockLanguageModelOptions{
		StreamResponse: testutil.MockTextResponse("complete", testutil.MockUsage(1, 1)),
	})

	firstRunner := newPermissionResumeRunner(tools, store, model, &order)
	first := permissionCheckpoint(t, "gated-a", calls)
	result, err := (&Service{}).dispatchResume(context.Background(), firstRunner, first, true)
	if err != nil {
		t.Fatalf("dispatchResume first approval: %v", err)
	}
	if result.Status != sol.RunSuspended || result.SuspensionContext == nil || result.SuspensionContext.ToolCallID != "gated-b" {
		t.Fatalf("first result = %#v, want suspension at gated-b", result)
	}
	if !reflect.DeepEqual(effects, []string{"gated_a", "safe"}) {
		t.Fatalf("effects after first approval = %v", effects)
	}
	if len(model.DoStreamCalls) != 0 {
		t.Fatalf("model calls after later gate = %d, want 0", len(model.DoStreamCalls))
	}
	wantFirstOrder := []string{
		"load", "persist:gated-a", "result:gated-a",
		"persist:safe", "result:safe", "permission:gated-b",
	}
	if !reflect.DeepEqual(order, wantFirstOrder) {
		t.Fatalf("first approval order = %v, want %v", order, wantFirstOrder)
	}

	order = nil
	secondRunner := newPermissionResumeRunner(tools, store, model, &order)
	second := permissionConversation(t, result.SuspensionContext)
	result, err = (&Service{}).dispatchResume(context.Background(), secondRunner, second, true)
	if err != nil {
		t.Fatalf("dispatchResume second approval: %v", err)
	}
	if result.Status != sol.RunCompleted {
		t.Fatalf("second result status = %s, want completed", result.Status)
	}
	if !reflect.DeepEqual(effects, []string{"gated_a", "safe", "gated_b", "tail"}) {
		t.Fatalf("effects after second approval = %v", effects)
	}
	if len(model.DoStreamCalls) != 1 {
		t.Fatalf("model calls after second approval = %d, want 1", len(model.DoStreamCalls))
	}
	wantSecondOrder := []string{
		"load", "persist:gated-b", "result:gated-b",
		"persist:tail", "result:tail", "load",
	}
	if !reflect.DeepEqual(order, wantSecondOrder) {
		t.Fatalf("second approval order = %v, want %v", order, wantSecondOrder)
	}
}

func TestDispatchResumeDenialSkipsOrderedTail(t *testing.T) {
	calls := []stream.ToolCall{
		{ID: "gated-a", Name: "gated_a"},
		{ID: "safe", Name: "safe"},
		{ID: "gated-b", Name: "gated_b"},
	}
	var effects, order []string
	tools := permissionResumeTools(&effects)
	store := &permissionResumeStore{
		messages: permissionAssistantHistory(calls),
		order:    &order,
	}
	model := testutil.NewMockLanguageModel(testutil.MockLanguageModelOptions{
		StreamResponse: testutil.MockTextResponse("denied", testutil.MockUsage(1, 1)),
	})
	runner := newPermissionResumeRunner(tools, store, model, &order)

	result, err := (&Service{}).dispatchResume(context.Background(), runner, permissionCheckpoint(t, "gated-a", calls), false)
	if err != nil {
		t.Fatalf("dispatchResume denial: %v", err)
	}
	if result.Status != sol.RunCompleted {
		t.Fatalf("result status = %s, want completed", result.Status)
	}
	if len(effects) != 0 {
		t.Fatalf("denial executed tools: %v", effects)
	}
	if len(model.DoStreamCalls) != 1 {
		t.Fatalf("model calls = %d, want 1", len(model.DoStreamCalls))
	}
	var resultIDs []string
	for _, entry := range order {
		if strings.HasPrefix(entry, "result:") {
			resultIDs = append(resultIDs, strings.TrimPrefix(entry, "result:"))
		}
	}
	if !reflect.DeepEqual(resultIDs, []string{"gated-a", "safe", "gated-b"}) {
		t.Fatalf("denial result order = %v", resultIDs)
	}
	wantReasons := map[string]string{
		"gated-a": "Execution was denied by the user.",
		"safe":    "This tool was not executed because an earlier tool call in the same ordered batch was denied by the user.",
		"gated-b": "This tool was not executed because an earlier tool call in the same ordered batch was denied by the user.",
	}
	for _, msg := range store.messages {
		if msg.Role != "tool" || len(msg.Parts) == 0 || msg.Parts[0].Tool == nil {
			continue
		}
		part := msg.Parts[0].Tool
		if part.Outcome != "denied" {
			t.Errorf("tool %s outcome = %q, want denied", part.CallID, part.Outcome)
		}
		if part.Output != wantReasons[part.CallID] {
			t.Errorf("tool %s reason = %q, want %q", part.CallID, part.Output, wantReasons[part.CallID])
		}
	}
}

func permissionAssistantHistory(calls []stream.ToolCall) []session.Message {
	parts := make([]goai.Part, len(calls))
	for i, call := range calls {
		parts[i] = goai.ToolCallPart{ID: call.ID, Name: call.Name, Input: call.Input}
	}
	return []session.Message{session.FromGoAIMessage(goai.NewAssistantMessageWithParts(parts...))}
}

func permissionResumeTools(effects *[]string) tool.Set {
	build := func(name string) tool.Tool {
		return tool.New(name).Description(name).Execute(func(_ context.Context, _ json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			*effects = append(*effects, name)
			return tool.Result{Output: name + " complete"}, nil
		}).Build()
	}
	return tool.Set{
		"gated_a": build("gated_a"),
		"safe":    build("safe"),
		"gated_b": build("gated_b"),
		"tail":    build("tail"),
	}
}

func newPermissionResumeRunner(tools tool.Set, store session.SessionStore, model stream.Model, order *[]string) *sol.Runner {
	exec := newGatedExecutor(tool.NewLocalExecutor(tools, nil))
	exec.isDestructive = func(name string) bool { return name == "gated_a" || name == "gated_b" }
	runBus := bus.New()
	runBus.Subscribe(bus.StreamToolResult, func(event bus.Event) {
		result := event.Properties.(stream.ToolResultEvent)
		*order = append(*order, "result:"+result.ToolCallID)
	})
	runBus.Subscribe(bus.PermissionAsked, func(event bus.Event) {
		asked := event.Properties.(bus.PermissionAskedPayload)
		*order = append(*order, "permission:"+asked.ToolCallID)
	})
	return sol.NewRunner(sol.RunnerOptions{
		Agent:        &agent.Agent{Name: "sysagent", Tools: tools, MaxSteps: 5},
		Executor:     exec,
		SessionStore: store,
		Model:        model,
		Bus:          runBus,
		Quiet:        true,
	})
}

func permissionCheckpoint(t *testing.T, currentID string, calls []stream.ToolCall) dbq.SystemConversation {
	t.Helper()
	return permissionConversation(t, &sol.SuspensionContext{
		Reason:           "permission",
		Data:             &bus.ErrPermissionNeeded{Permission: "test", ToolCallID: currentID},
		ToolCallID:       currentID,
		PendingToolCalls: calls,
	})
}

func permissionConversation(t *testing.T, suspension *sol.SuspensionContext) dbq.SystemConversation {
	t.Helper()
	checkpoint, err := json.Marshal(suspension)
	if err != nil {
		t.Fatalf("marshal permission checkpoint: %v", err)
	}
	return dbq.SystemConversation{Checkpoint: checkpoint}
}

type permissionResumeStore struct {
	messages []session.Message
	order    *[]string
}

func (s *permissionResumeStore) Load(context.Context) ([]session.Message, error) {
	*s.order = append(*s.order, "load")
	return append([]session.Message(nil), s.messages...), nil
}

func (s *permissionResumeStore) Append(_ context.Context, messages []session.Message) error {
	for _, msg := range messages {
		if len(msg.Parts) > 0 && msg.Parts[0].Tool != nil {
			*s.order = append(*s.order, "persist:"+msg.Parts[0].Tool.CallID)
		}
	}
	s.messages = append(s.messages, messages...)
	return nil
}

func (*permissionResumeStore) Compact(context.Context, []session.Message, int) error { return nil }

type suspendedSystemFixture struct {
	service        *Service
	principal      authz.Principal
	conversationID uuid.UUID
	runID          uuid.UUID
}

func newSuspendedSystemFixture(t *testing.T) suspendedSystemFixture {
	t.Helper()
	requireSysagentTestDB(t)
	ctx := context.Background()
	q := dbq.New(sysagentTestDB.Pool())
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	user, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:       "sysagent-" + suffix + "@example.com",
		DisplayName: "System Agent Test",
		TenantRole:  string(auth.RoleUser),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	conversation, err := q.CreateSystemConversation(ctx, dbq.CreateSystemConversationParams{
		UserID: user.ID,
		Title:  "confirmation test",
	})
	if err != nil {
		t.Fatalf("CreateSystemConversation: %v", err)
	}
	run, err := q.CreateSystemRun(ctx, dbq.CreateSystemRunParams{
		ConversationID: conversation.ID,
		UserID:         user.ID,
		TriggerType:    "prompt",
	})
	if err != nil {
		t.Fatalf("CreateSystemRun: %v", err)
	}
	svc := &Service{db: sysagentTestDB, logger: zap.NewNop()}
	if err := svc.persistSuspension(ctx, uuid.UUID(conversation.ID.Bytes), uuid.UUID(run.ID.Bytes), &sol.SuspensionContext{Reason: "permission"}); err != nil {
		t.Fatalf("persistSuspension: %v", err)
	}
	return suspendedSystemFixture{
		service:        svc,
		principal:      authz.UserPrincipal(uuid.UUID(user.ID.Bytes), auth.RoleUser),
		conversationID: uuid.UUID(conversation.ID.Bytes),
		runID:          uuid.UUID(run.ID.Bytes),
	}
}

func TestStartRunConcurrentConfirmationReplay(t *testing.T) {
	fixture := newSuspendedSystemFixture(t)
	approved := true
	input := PromptInput{Approved: &approved, ResumeRunID: fixture.runID.String(), Platform: "web"}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := fixture.service.startRun(context.Background(), fixture.principal, fixture.conversationID, input)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	var succeeded, conflicted int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, service.ErrConflict):
			conflicted++
		default:
			t.Fatalf("startRun error = %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("successes = %d, conflicts = %d; want 1 each", succeeded, conflicted)
	}

	var runCount int
	if err := sysagentTestDB.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM system_runs WHERE conversation_id = $1`, fixture.conversationID).Scan(&runCount); err != nil {
		t.Fatalf("count system runs: %v", err)
	}
	if runCount != 2 {
		t.Fatalf("system run count = %d, want suspended run plus one successor", runCount)
	}
	assertResolvedSystemCheckpoint(t, fixture.conversationID, fixture.runID)
}

func TestStartRunRejectsStaleRunForLaterCheckpoint(t *testing.T) {
	fixture := newSuspendedSystemFixture(t)
	ctx := context.Background()
	q := dbq.New(sysagentTestDB.Pool())
	conversation, err := q.GetSystemConversationByID(ctx, pgtype.UUID{Bytes: fixture.conversationID, Valid: true})
	if err != nil {
		t.Fatalf("GetSystemConversationByID: %v", err)
	}
	later, err := q.CreateSystemRun(ctx, dbq.CreateSystemRunParams{
		ConversationID: conversation.ID,
		UserID:         conversation.UserID,
		TriggerType:    "prompt",
	})
	if err != nil {
		t.Fatalf("CreateSystemRun later: %v", err)
	}
	suspended, err := q.SuspendSystemRun(ctx, dbq.SuspendSystemRunParams{ID: later.ID, ConversationID: conversation.ID})
	if err != nil || suspended != 1 {
		t.Fatalf("suspend later run: rows=%d err=%v", suspended, err)
	}
	if _, err := sysagentTestDB.Pool().Exec(ctx, `
		UPDATE system_conversations
		SET checkpoint = '{"reason":"later"}'::jsonb, suspended_run_id = $1
		WHERE id = $2`, later.ID, conversation.ID); err != nil {
		t.Fatalf("install later checkpoint: %v", err)
	}

	approved := true
	_, _, err = fixture.service.startRun(ctx, fixture.principal, fixture.conversationID, PromptInput{
		Approved:    &approved,
		ResumeRunID: fixture.runID.String(),
		Platform:    "web",
	})
	if !errors.Is(err, service.ErrConflict) {
		t.Fatalf("startRun stale error = %v, want conflict", err)
	}

	stale, err := q.GetSystemRunByID(ctx, pgtype.UUID{Bytes: fixture.runID, Valid: true})
	if err != nil {
		t.Fatalf("GetSystemRunByID stale: %v", err)
	}
	fresh, err := q.GetSystemConversationByID(ctx, conversation.ID)
	if err != nil {
		t.Fatalf("GetSystemConversationByID fresh: %v", err)
	}
	if stale.Status != "suspended" {
		t.Fatalf("stale run status = %q, want suspended", stale.Status)
	}
	if !fresh.SuspendedRunID.Valid || fresh.SuspendedRunID.Bytes != later.ID.Bytes || string(fresh.Checkpoint) != `{"reason": "later"}` {
		t.Fatalf("later checkpoint changed: run = %v checkpoint = %s", fresh.SuspendedRunID, fresh.Checkpoint)
	}
}

func TestStartRunRollsBackClaimWhenSuccessorCreationFails(t *testing.T) {
	fixture := newSuspendedSystemFixture(t)
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	functionName := "fail_system_successor_" + suffix
	triggerName := "fail_system_successor_" + suffix
	if _, err := sysagentTestDB.Pool().Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'forced successor failure'; END
		$$`, functionName)); err != nil {
		t.Fatalf("create failure function: %v", err)
	}
	if _, err := sysagentTestDB.Pool().Exec(ctx, fmt.Sprintf(`
		CREATE TRIGGER %s BEFORE INSERT ON system_runs
		FOR EACH ROW WHEN (NEW.conversation_id = '%s'::uuid)
		EXECUTE FUNCTION %s()`, triggerName, fixture.conversationID, functionName)); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sysagentTestDB.Pool().Exec(context.Background(), fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON system_runs", triggerName))
		_, _ = sysagentTestDB.Pool().Exec(context.Background(), fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", functionName))
	})

	approved := true
	input := PromptInput{Approved: &approved, ResumeRunID: fixture.runID.String(), Platform: "web"}
	if _, _, err := fixture.service.startRun(ctx, fixture.principal, fixture.conversationID, input); err == nil {
		t.Fatal("startRun succeeded with rejecting insert trigger")
	}
	assertPendingSystemCheckpoint(t, fixture.conversationID, fixture.runID)

	if _, err := sysagentTestDB.Pool().Exec(ctx, fmt.Sprintf("DROP TRIGGER %s ON system_runs", triggerName)); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	if _, _, err := fixture.service.startRun(ctx, fixture.principal, fixture.conversationID, input); err != nil {
		t.Fatalf("retry startRun: %v", err)
	}
	assertResolvedSystemCheckpoint(t, fixture.conversationID, fixture.runID)
}

func assertPendingSystemCheckpoint(t *testing.T, conversationID, runID uuid.UUID) {
	t.Helper()
	q := dbq.New(sysagentTestDB.Pool())
	conversation, err := q.GetSystemConversationByID(context.Background(), pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		t.Fatalf("GetSystemConversationByID: %v", err)
	}
	run, err := q.GetSystemRunByID(context.Background(), pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		t.Fatalf("GetSystemRunByID: %v", err)
	}
	if conversation.Status != "awaiting_confirmation" || len(conversation.Checkpoint) == 0 || !conversation.SuspendedRunID.Valid || conversation.SuspendedRunID.Bytes != runID {
		t.Fatalf("checkpoint is not pending for run %s: %#v", runID, conversation)
	}
	if run.Status != "suspended" {
		t.Fatalf("run status = %q, want suspended", run.Status)
	}
}

func assertResolvedSystemCheckpoint(t *testing.T, conversationID, runID uuid.UUID) {
	t.Helper()
	q := dbq.New(sysagentTestDB.Pool())
	conversation, err := q.GetSystemConversationByID(context.Background(), pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		t.Fatalf("GetSystemConversationByID: %v", err)
	}
	run, err := q.GetSystemRunByID(context.Background(), pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil {
		t.Fatalf("GetSystemRunByID: %v", err)
	}
	if conversation.Status != "active" || len(conversation.Checkpoint) != 0 || conversation.SuspendedRunID.Valid {
		t.Fatalf("checkpoint was not cleared: %#v", conversation)
	}
	if run.Status != "complete" {
		t.Fatalf("resolved run status = %q, want complete", run.Status)
	}
}
