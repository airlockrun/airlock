package agentapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCreateScheduledFireIsIdempotent(t *testing.T) {
	skipIfNoDB(t)
	agentID, _ := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	if err := q.UpsertScheduleHandler(t.Context(), dbq.UpsertScheduleHandlerParams{
		AgentID: toPgUUID(agentID), Slug: "remind", Kind: "schedule", TimeoutMs: 30000, Description: "Reminder",
	}); err != nil {
		t.Fatal(err)
	}
	h := testAgentHandler()
	router := testRouter(h, func(r chi.Router) { r.Post("/api/agent/schedules", h.CreateScheduledFire) })
	id := uuid.New()
	fireAt := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	request := wire.ScheduleRequest{ID: id.String(), Slug: "remind", FireAt: fireAt}

	for range 2 {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, agentRequest(t, http.MethodPost, "/api/agent/schedules", agentID, request))
		if w.Code != http.StatusNoContent {
			t.Fatalf("identical arm status = %d, body=%s", w.Code, w.Body.String())
		}
	}
	existing, err := q.GetScheduledFire(t.Context(), dbq.GetScheduledFireParams{ID: toPgUUID(id), AgentID: toPgUUID(agentID)})
	if err != nil {
		t.Fatal(err)
	}
	if existing.Attempt != 0 || existing.Status != "pending" || !existing.FireAt.Time.Equal(fireAt) {
		t.Fatalf("occurrence = %+v", existing)
	}

	request.FireAt = fireAt.Add(time.Minute)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, agentRequest(t, http.MethodPost, "/api/agent/schedules", agentID, request))
	if w.Code != http.StatusConflict {
		t.Fatalf("conflicting arm status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
}

func TestScheduledFireLeaseReclaimRejectsStaleAck(t *testing.T) {
	skipIfNoDB(t)
	agentID, _ := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	id := uuid.New()
	if n, err := q.InsertScheduledFire(t.Context(), dbq.InsertScheduledFireParams{
		ID: toPgUUID(id), AgentID: toPgUUID(agentID), Source: "schedule", Slug: "remind",
		FireAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}, TimeoutMs: 1000, MaxAttempts: 3,
	}); err != nil || n != 1 {
		t.Fatalf("InsertScheduledFire = (%d, %v)", n, err)
	}
	first, err := q.ClaimDueScheduledFires(t.Context(), dbq.ClaimDueScheduledFiresParams{LeaseOwner: toPgUUID(uuid.New()), BatchSize: 1})
	if err != nil || len(first) != 1 || first[0].Attempt != 1 {
		t.Fatalf("first claim = (%+v, %v)", first, err)
	}
	if _, err := testDB.Pool().Exec(t.Context(), `UPDATE agent_scheduled_fires SET lease_expires_at = now() - interval '1 second' WHERE agent_id = $1 AND id = $2`, toPgUUID(agentID), toPgUUID(id)); err != nil {
		t.Fatal(err)
	}
	second, err := q.ClaimDueScheduledFires(t.Context(), dbq.ClaimDueScheduledFiresParams{LeaseOwner: toPgUUID(uuid.New()), BatchSize: 1})
	if err != nil || len(second) != 1 || second[0].Attempt != 2 || second[0].LeaseToken == first[0].LeaseToken {
		t.Fatalf("second claim = (%+v, %v)", second, err)
	}
	if n, err := q.CompleteScheduledFire(t.Context(), dbq.CompleteScheduledFireParams{ID: first[0].ID, AgentID: first[0].AgentID, LeaseToken: first[0].LeaseToken}); err != nil || n != 0 {
		t.Fatalf("stale completion = (%d, %v), want 0", n, err)
	}
	if n, err := q.CompleteScheduledFire(t.Context(), dbq.CompleteScheduledFireParams{ID: second[0].ID, AgentID: second[0].AgentID, LeaseToken: second[0].LeaseToken}); err != nil || n != 1 {
		t.Fatalf("current completion = (%d, %v), want 1", n, err)
	}
}

func TestCronLogicalOccurrenceIsUnique(t *testing.T) {
	skipIfNoDB(t)
	agentID, _ := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	fireAt := pgtype.Timestamptz{Time: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond), Valid: true}
	insert := func(id uuid.UUID) (int64, error) {
		return q.InsertScheduledFire(t.Context(), dbq.InsertScheduledFireParams{
			ID: toPgUUID(id), AgentID: toPgUUID(agentID), Source: "cron", Slug: "daily", FireAt: fireAt,
			Recurrence: "0 9 * * *", TimeoutMs: 30000, MaxAttempts: 5,
		})
	}
	if n, err := insert(uuid.New()); err != nil || n != 1 {
		t.Fatalf("first insert = (%d, %v)", n, err)
	}
	if n, err := insert(uuid.New()); err != nil || n != 0 {
		t.Fatalf("duplicate logical insert = (%d, %v), want 0", n, err)
	}
}
