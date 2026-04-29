package api

import (
	"context"
	"net/http"
	"time"

	"github.com/airlockrun/airlock/db"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/storage"
	"go.uber.org/zap"
)

type healthHandler struct {
	db     *db.DB
	s3     *storage.S3Client
	logger *zap.Logger
}

func newHealthHandler(d *db.DB, s3 *storage.S3Client, logger *zap.Logger) *healthHandler {
	if d == nil {
		panic("api: healthHandler requires DB")
	}
	if s3 == nil {
		panic("api: healthHandler requires S3Client")
	}
	return &healthHandler{db: d, s3: s3, logger: logger}
}

// Check probes Postgres and S3 with a short timeout. Returns 200 + status="ok"
// if both reachable; 503 + status="degraded" otherwise. Per-subsystem booleans
// in the response body show which dep is down.
func (h *healthHandler) Check(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	dbOK := h.db.Pool().Ping(ctx) == nil
	s3OK := h.s3.Ping(ctx) == nil

	status := "ok"
	httpStatus := http.StatusOK
	if !dbOK || !s3OK {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
		h.logger.Warn("health check degraded", zap.Bool("db", dbOK), zap.Bool("s3", s3OK))
	}

	writeProto(w, httpStatus, &airlockv1.HealthResponse{
		Status: status,
		Db:     dbOK,
		S3:     s3OK,
	})
}
