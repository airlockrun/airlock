package api

import (
	"context"
	"testing"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// insertRunRaw seeds a runs row with explicit finished_at, verbose content,
// and aggregate values so CompactOldRuns behavior can be asserted across
// each WHERE-clause branch.
func insertRunRaw(t *testing.T, agentID uuid.UUID, finishedAt *time.Time, verbose bool, compacted bool) uuid.UUID {
	t.Helper()
	runID := uuid.New()
	var finished pgtype.Timestamptz
	if finishedAt != nil {
		finished = pgtype.Timestamptz{Time: *finishedAt, Valid: true}
	}
	inputPayload := []byte(`{}`)
	actions := []byte(`[]`)
	logs, stdout, panic := "", "", ""
	var checkpoint []byte
	if verbose {
		inputPayload = []byte(`{"msg":"hello"}`)
		actions = []byte(`[{"type":"tool_call"}]`)
		logs = "some log output"
		stdout = "stdout line"
		panic = "stack trace"
		checkpoint = []byte(`{"state":"x"}`)
	}
	_, err := testDB.Pool().Exec(context.Background(),
		`INSERT INTO runs (id, agent_id, status, input_payload, actions, logs, stdout_log, panic_trace, checkpoint, llm_tokens_in, llm_tokens_out, llm_cost_estimate, source_ref, trigger_type, trigger_ref, compacted, finished_at)
		 VALUES ($1, $2, 'success', $3, $4, $5, $6, $7, $8, 100, 200, 0.003, '', 'prompt', '', $9, $10)`,
		toPgUUID(runID), toPgUUID(agentID), inputPayload, actions, logs, stdout, panic, checkpoint, compacted, finished,
	)
	if err != nil {
		t.Fatalf("insert run: %v", err)
	}
	return runID
}

func TestCompactOldRuns(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()

	agentID, _ := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())

	old := time.Now().Add(-31 * 24 * time.Hour)
	recent := time.Now().Add(-time.Hour)

	oldVerbose := insertRunRaw(t, agentID, &old, true, false)
	oldAlreadyCompacted := insertRunRaw(t, agentID, &old, false, true)
	freshVerbose := insertRunRaw(t, agentID, &recent, true, false)
	unfinished := insertRunRaw(t, agentID, nil, true, false)

	cutoff := pgtype.Timestamptz{Time: time.Now().Add(-30 * 24 * time.Hour), Valid: true}
	n, err := q.CompactOldRuns(ctx, cutoff)
	if err != nil {
		t.Fatalf("CompactOldRuns: %v", err)
	}
	if n != 1 {
		t.Errorf("rows affected = %d, want 1 (only oldVerbose matches)", n)
	}

	// oldVerbose: verbose cleared, aggregates intact, compacted=true.
	got, err := q.GetRunByID(ctx, toPgUUID(oldVerbose))
	if err != nil {
		t.Fatalf("GetRunByID oldVerbose: %v", err)
	}
	if string(got.InputPayload) != "{}" {
		t.Errorf("oldVerbose.InputPayload = %q, want '{}'", string(got.InputPayload))
	}
	if string(got.Actions) != "[]" {
		t.Errorf("oldVerbose.Actions = %q, want '[]'", string(got.Actions))
	}
	if got.Checkpoint != nil {
		t.Errorf("oldVerbose.Checkpoint = %q, want nil", string(got.Checkpoint))
	}
	if got.Logs != "" || got.StdoutLog != "" || got.PanicTrace != "" {
		t.Errorf("oldVerbose text fields not cleared: logs=%q stdout=%q panic=%q", got.Logs, got.StdoutLog, got.PanicTrace)
	}
	if !got.Compacted {
		t.Error("oldVerbose.Compacted = false, want true")
	}
	if got.LlmTokensIn != 100 || got.LlmTokensOut != 200 {
		t.Errorf("oldVerbose tokens clobbered: in=%d out=%d", got.LlmTokensIn, got.LlmTokensOut)
	}

	// oldAlreadyCompacted: WHERE clause excluded it — row stays compacted,
	// no rewrite (can't directly observe a no-op, but n==1 above proves only
	// one row was touched).
	got, err = q.GetRunByID(ctx, toPgUUID(oldAlreadyCompacted))
	if err != nil {
		t.Fatalf("GetRunByID oldAlreadyCompacted: %v", err)
	}
	if !got.Compacted {
		t.Error("oldAlreadyCompacted.Compacted = false, want true")
	}

	// freshVerbose: newer than cutoff, stays verbose.
	got, err = q.GetRunByID(ctx, toPgUUID(freshVerbose))
	if err != nil {
		t.Fatalf("GetRunByID freshVerbose: %v", err)
	}
	if string(got.InputPayload) == "{}" {
		t.Error("freshVerbose.InputPayload was compacted; should have been skipped")
	}
	if got.Compacted {
		t.Error("freshVerbose.Compacted = true, want false")
	}

	// unfinished: finished_at IS NULL, stays verbose.
	got, err = q.GetRunByID(ctx, toPgUUID(unfinished))
	if err != nil {
		t.Fatalf("GetRunByID unfinished: %v", err)
	}
	if got.Compacted {
		t.Error("unfinished.Compacted = true, want false")
	}
}
