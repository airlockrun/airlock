package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	runssvc "github.com/airlockrun/airlock/service/runs"
	"github.com/airlockrun/airlock/storage"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

type runsHandler struct {
	svc    *runssvc.Service
	s3     *storage.S3Client
	logger *zap.Logger
}

func newRunsHandler(svc *runssvc.Service, s3 *storage.S3Client, logger *zap.Logger) *runsHandler {
	if svc == nil {
		panic("api: runs.Service is required")
	}
	if s3 == nil {
		panic("api: s3 client is required")
	}
	if logger == nil {
		panic("api: logger is required")
	}
	return &runsHandler{svc: svc, s3: s3, logger: logger}
}

func writeRunsError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	var msg string
	switch {
	case errors.Is(err, service.ErrNotFound):
		msg = "run not found"
	case errors.Is(err, service.ErrConflict):
		msg = "run is not running"
	default:
		msg = fallback
	}
	writeError(w, status, msg)
}

// ListRuns handles GET /api/v1/agents/{agentID}/runs.
func (h *runsHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	var cursor time.Time
	if c := r.URL.Query().Get("cursor"); c != "" {
		if t, err := time.Parse(time.RFC3339Nano, c); err == nil {
			cursor = t
		}
	}
	res, err := h.svc.List(r.Context(), agentID, cursor, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list runs")
		return
	}
	out := make([]*airlockv1.RunInfo, len(res.Runs))
	for i, run := range res.Runs {
		out[i] = runToProto(run, false)
	}
	var nextCursor string
	if !res.NextCursor.IsZero() {
		nextCursor = res.NextCursor.Format(time.RFC3339Nano)
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
	res, err := h.svc.Get(ctx, runID)
	if err != nil {
		writeRunsError(w, err, "failed to load run")
		return
	}
	msgInfos := make([]*airlockv1.AgentMessageInfo, len(res.Messages))
	for i, m := range res.Messages {
		msgInfos[i] = messageToProto(ctx, h.s3, h.logger, m)
	}
	writeProto(w, http.StatusOK, &airlockv1.GetRunResponse{
		Run:      runToProto(res.Run, true),
		Messages: msgInfos,
	})
}

// GetRunLogs handles GET /api/v1/runs/{runID}/logs.
func (h *runsHandler) GetRunLogs(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUID(chi.URLParam(r, "runID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid run ID")
		return
	}
	logs, err := h.svc.Logs(r.Context(), runID)
	if err != nil {
		writeRunsError(w, err, "failed to load logs")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(logs))
}

// CancelRun handles DELETE /api/v1/runs/{runID}.
func (h *runsHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUID(chi.URLParam(r, "runID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid run ID")
		return
	}
	if err := h.svc.Cancel(r.Context(), runID); err != nil {
		writeRunsError(w, err, "failed to cancel run")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- shared proto helpers (still used by conversations.go etc) ---

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
		LlmTokensIn:     r.LlmTokensIn,
		LlmTokensOut:    r.LlmTokensOut,
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
