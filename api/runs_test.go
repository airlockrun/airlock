package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// fakeDispatcher implements the runDispatcher interface for handler tests.
type fakeDispatcher struct {
	cancelCalled  []uuid.UUID
	cancelReturns map[uuid.UUID]bool

	extendCalled  []uuid.UUID
	extendReturns map[uuid.UUID]extendReply
}

type extendReply struct {
	deadline  time.Time
	remaining int
	err       error
}

func (f *fakeDispatcher) CancelRun(runID uuid.UUID) bool {
	f.cancelCalled = append(f.cancelCalled, runID)
	if r, ok := f.cancelReturns[runID]; ok {
		return r
	}
	return false
}

func (f *fakeDispatcher) ExtendRun(runID uuid.UUID, _ time.Duration) (time.Time, int, error) {
	f.extendCalled = append(f.extendCalled, runID)
	if r, ok := f.extendReturns[runID]; ok {
		return r.deadline, r.remaining, r.err
	}
	return time.Time{}, 0, trigger.ErrRunNotInFlight
}

// newRunsTestHandler returns a runsHandler wired to a fake dispatcher and
// no DB / S3. Sufficient for endpoints that don't read the runs table.
func newRunsTestHandler(disp runDispatcher) *runsHandler {
	return &runsHandler{
		dispatcher: disp,
		logger:     zap.NewNop(),
	}
}

func newRunRequest(t *testing.T, method, path string, runID uuid.UUID) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("runID", runID.String())
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// --- ExtendRun handler ---

func TestExtendRun_Success(t *testing.T) {
	runID := uuid.New()
	deadline := time.Now().Add(7 * time.Minute).Truncate(time.Millisecond)
	disp := &fakeDispatcher{
		extendReturns: map[uuid.UUID]extendReply{
			runID: {deadline: deadline, remaining: 3, err: nil},
		},
	}
	h := newRunsTestHandler(disp)

	rec := httptest.NewRecorder()
	h.ExtendRun(rec, newRunRequest(t, "POST", "/api/v1/runs/"+runID.String()+"/extend", runID))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// proto JSON marshals int64 as a JSON string (proto3 convention) —
	// the frontend reads with `Number(data.deadlineMs)`.
	var body struct {
		DeadlineMs          string `json:"deadlineMs"`
		ExtensionsRemaining int32  `json:"extensionsRemaining"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	gotMs, err := strconv.ParseInt(body.DeadlineMs, 10, 64)
	if err != nil {
		t.Fatalf("parse deadlineMs %q: %v", body.DeadlineMs, err)
	}
	if gotMs != deadline.UnixMilli() {
		t.Errorf("deadlineMs = %d, want %d", gotMs, deadline.UnixMilli())
	}
	if body.ExtensionsRemaining != 3 {
		t.Errorf("extensionsRemaining = %d, want 3", body.ExtensionsRemaining)
	}
	if len(disp.extendCalled) != 1 || disp.extendCalled[0] != runID {
		t.Errorf("dispatcher.ExtendRun calls = %v, want [%s]", disp.extendCalled, runID)
	}
}

func TestExtendRun_NotInFlight_Returns404(t *testing.T) {
	runID := uuid.New()
	disp := &fakeDispatcher{
		extendReturns: map[uuid.UUID]extendReply{
			runID: {err: trigger.ErrRunNotInFlight},
		},
	}
	h := newRunsTestHandler(disp)

	rec := httptest.NewRecorder()
	h.ExtendRun(rec, newRunRequest(t, "POST", "/api/v1/runs/"+runID.String()+"/extend", runID))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestExtendRun_CeilingReached_Returns409(t *testing.T) {
	runID := uuid.New()
	disp := &fakeDispatcher{
		extendReturns: map[uuid.UUID]extendReply{
			runID: {err: trigger.ErrExtensionCeiling},
		},
	}
	h := newRunsTestHandler(disp)

	rec := httptest.NewRecorder()
	h.ExtendRun(rec, newRunRequest(t, "POST", "/api/v1/runs/"+runID.String()+"/extend", runID))

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestExtendRun_InvalidUUID_Returns400(t *testing.T) {
	disp := &fakeDispatcher{}
	h := newRunsTestHandler(disp)

	req := httptest.NewRequest("POST", "/api/v1/runs/not-a-uuid/extend", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("runID", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	h.ExtendRun(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if len(disp.extendCalled) != 0 {
		t.Errorf("dispatcher should not be called on bad UUID; got %v", disp.extendCalled)
	}
}

func TestExtendRun_NilDispatcher_Returns503(t *testing.T) {
	h := newRunsTestHandler(nil)
	runID := uuid.New()

	rec := httptest.NewRecorder()
	h.ExtendRun(rec, newRunRequest(t, "POST", "/api/v1/runs/"+runID.String()+"/extend", runID))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestExtendRun_UnexpectedError_Returns500(t *testing.T) {
	runID := uuid.New()
	disp := &fakeDispatcher{
		extendReturns: map[uuid.UUID]extendReply{
			runID: {err: errors.New("boom")},
		},
	}
	h := newRunsTestHandler(disp)

	rec := httptest.NewRecorder()
	h.ExtendRun(rec, newRunRequest(t, "POST", "/api/v1/runs/"+runID.String()+"/extend", runID))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// --- CancelRun handler (signals dispatcher; DB write needs Postgres) ---
//
// CancelRun also writes a "cancelled" row to the DB. That path is exercised
// by the manual-cancel verification step; here we cover the dispatcher
// signalling slice without standing up Postgres by short-circuiting on the
// "run not running" guard via a fake DB-less handler. Limited coverage —
// the test confirms the dispatcher gets called with the right UUID before
// the DB read returns "not found" and bails out.
//
// Skipped because the DB lookup happens before the dispatcher call in the
// current handler; without a test Postgres we'd need to invert the
// ordering or wire a fake db.DB. Left as a follow-up if the cancel path
// regresses.

func TestExtendRun_ResponseHasContentType(t *testing.T) {
	runID := uuid.New()
	disp := &fakeDispatcher{
		extendReturns: map[uuid.UUID]extendReply{
			runID: {deadline: time.Now().Add(time.Minute), remaining: 4},
		},
	}
	h := newRunsTestHandler(disp)

	rec := httptest.NewRecorder()
	h.ExtendRun(rec, newRunRequest(t, "POST", "/api/v1/runs/"+runID.String()+"/extend", runID))

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
}
