package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

// runDispatcher is the slice of *trigger.Dispatcher that runsHandler
// actually calls. Pulled out so handler tests can mock without standing
// up containers, DB, encryptor, etc. The real Dispatcher satisfies it.
type runDispatcher interface {
	CancelRun(runID uuid.UUID) bool
	ExtendRun(runID uuid.UUID, by time.Duration) (time.Time, int, error)
}

type runsHandler struct {
	db         *db.DB
	dispatcher runDispatcher
	s3         *storage.S3Client
	logger     *zap.Logger
}

// ListRuns handles GET /api/v1/agents/{agentID}/runs.
func (h *runsHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())

	// Parse cursor (ISO timestamp) and limit.
	var cursor pgtype.Timestamptz
	if c := r.URL.Query().Get("cursor"); c != "" {
		t, err := time.Parse(time.RFC3339Nano, c)
		if err == nil {
			cursor = pgtype.Timestamptz{Time: t, Valid: true}
		}
	}
	limit := int32(50)
	// (could parse ?limit= here, but 50 is a reasonable default)

	runs, err := q.ListRunsByAgent(ctx, dbq.ListRunsByAgentParams{
		AgentID: toPgUUID(agentID),
		Cursor:  cursor,
		Lim:     limit,
	})
	if err != nil {
		h.logger.Error("list runs", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list runs")
		return
	}

	out := make([]*airlockv1.RunInfo, len(runs))
	for i, r := range runs {
		out[i] = runToProto(r, false)
	}

	var nextCursor string
	if len(runs) == int(limit) {
		last := runs[len(runs)-1]
		nextCursor = last.StartedAt.Time.Format(time.RFC3339Nano)
	}

	writeProto(w, http.StatusOK, &airlockv1.ListRunsResponse{
		Runs:       out,
		NextCursor: nextCursor,
	})
}

// GetRun handles GET /api/v1/runs/{runID}.
func (h *runsHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	runID, err := parseUUID(chi.URLParam(r, "runID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid run ID")
		return
	}

	q := dbq.New(h.db.Pool())
	run, err := q.GetRunByID(ctx, toPgUUID(runID))
	if err != nil {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}

	// Load messages produced during this run.
	msgs, _ := q.ListMessagesByRun(ctx, toPgUUID(runID))
	msgInfos := make([]*airlockv1.AgentMessageInfo, len(msgs))
	for i, m := range msgs {
		msgInfos[i] = messageToProto(ctx, h.s3, h.logger, m)
	}

	writeProto(w, http.StatusOK, &airlockv1.GetRunResponse{
		Run:      runToProto(run, true),
		Messages: msgInfos,
	})
}

// GetRunLogs handles GET /api/v1/runs/{runID}/logs.
func (h *runsHandler) GetRunLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	runID, err := parseUUID(chi.URLParam(r, "runID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid run ID")
		return
	}

	q := dbq.New(h.db.Pool())
	run, err := q.GetRunByID(ctx, toPgUUID(runID))
	if err != nil {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(run.StdoutLog))
}

// CancelRun handles DELETE /api/v1/runs/{runID}. Fires the dispatcher's
// per-run cancel hook if one is registered (cancels the outbound HTTP
// request to the agent → run.ctx fires inside the agent → vm.Interrupt
// aborts run_js → agent's detached r.Complete POST lands the terminal
// state). Also marks the row cancelled directly here as belt-and-
// suspenders: if the agent's r.Complete never arrives (crashed mid-tool,
// network partition), the sweeper or this DB write is what flips the
// row out of 'running'.
func (h *runsHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	runID, err := parseUUID(chi.URLParam(r, "runID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid run ID")
		return
	}

	q := dbq.New(h.db.Pool())
	run, err := q.GetRunByID(ctx, toPgUUID(runID))
	if err != nil {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}

	if run.Status != "running" {
		writeError(w, http.StatusConflict, "run is not running")
		return
	}

	// Signal the agent first; the streaming /prompt connection breaks,
	// publishRunEvents exits, and the conversation mutex releases for
	// any prompt queued behind this run.
	if h.dispatcher != nil {
		h.dispatcher.CancelRun(runID)
	}

	// Mark as cancelled in DB. Idempotent with the agent's own
	// r.Complete POST (UpsertRunComplete) — last write wins.
	_ = q.UpdateRunComplete(ctx, dbq.UpdateRunCompleteParams{
		ID:           toPgUUID(runID),
		Status:       "cancelled",
		ErrorMessage: "cancelled by user",
	})

	w.WriteHeader(http.StatusNoContent)
}

// ExtendRun handles POST /api/v1/runs/{runID}/extend. Pushes the
// dispatcher's per-run deadline timer by trigger.ExtendIncrement, up to
// trigger.MaxExtensions times. The server picks the increment so a
// malicious client can't request multi-hour extensions; clients just call
// repeatedly until extensions_remaining hits 0.
func (h *runsHandler) ExtendRun(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUID(chi.URLParam(r, "runID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid run ID")
		return
	}

	if h.dispatcher == nil {
		writeError(w, http.StatusServiceUnavailable, "dispatcher unavailable")
		return
	}

	deadline, remaining, err := h.dispatcher.ExtendRun(runID, trigger.ExtendIncrement)
	switch {
	case errors.Is(err, trigger.ErrRunNotInFlight):
		writeError(w, http.StatusNotFound, "run not in flight")
		return
	case errors.Is(err, trigger.ErrExtensionCeiling):
		writeError(w, http.StatusConflict, "max extensions reached")
		return
	case err != nil:
		h.logger.Error("extend run", zap.String("run_id", runID.String()), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "extend failed")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.ExtendRunResponse{
		DeadlineMs:          deadline.UnixMilli(),
		ExtensionsRemaining: int32(remaining),
	})
}

// --- helpers ---

func runToProto(r dbq.Run, detail bool) *airlockv1.RunInfo {
	info := &airlockv1.RunInfo{
		Id:              convert.PgUUIDToString(r.ID),
		AgentId:         convert.PgUUIDToString(r.AgentID),
		BridgeId:        convert.PgUUIDToString(r.BridgeID),
		Status:          r.Status,
		StartedAt:       convert.PgTimestampToProto(r.StartedAt),
		FinishedAt:      convert.PgTimestampToProto(r.FinishedAt),
		DurationMs:      r.DurationMs.Int32,
		ErrorMessage:    r.ErrorMessage,
		ErrorKind:       r.ErrorKind,
		LlmTokensIn:    r.LlmTokensIn,
		LlmTokensOut:   r.LlmTokensOut,
		LlmCostEstimate: pgNumericToFloat(r.LlmCostEstimate),
		SourceRef:       r.SourceRef,
	}

	if detail {
		info.InputPayload = jsonToStruct(r.InputPayload)
		info.Actions = jsonToListValue(r.Actions)
		info.StdoutLog = r.StdoutLog
		info.PanicTrace = r.PanicTrace
	}

	return info
}

func jsonToStruct(data []byte) *structpb.Struct {
	if len(data) == 0 || string(data) == "{}" || string(data) == "null" {
		return nil
	}
	return convert.AnyToStruct(data)
}

func jsonToListValue(data []byte) *structpb.ListValue {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil
	}
	var items []any
	if err := json.Unmarshal(data, &items); err != nil {
		return nil
	}
	lv, _ := structpb.NewList(items)
	return lv
}

func pgNumericToFloat(n pgtype.Numeric) float64 {
	f, _ := n.Float64Value()
	return f.Float64
}
