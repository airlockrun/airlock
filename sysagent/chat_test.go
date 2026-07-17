package sysagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/bus"
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
