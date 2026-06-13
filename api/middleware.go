package api

import (
	"context"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/airlockrun/airlock/auth"
	chimw "github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

type loggerKey struct{}

// reqLogger is a mutable logger holder stored in context.
// requestLogger sets the initial fields; identityLogger enriches it with uid/email.
// The access log reads the final state after the handler chain completes.
type reqLogger struct {
	logger *zap.Logger
}

// requestLogger creates a per-request logger enriched with method, path, IP,
// and request_id, then stores it in context for handlers to use via logFor.
// It also logs every completed request with status code and duration.
func requestLogger(base *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			logger := base.With(
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("ip", r.RemoteAddr),
			)
			if reqID := chimw.GetReqID(r.Context()); reqID != "" {
				logger = logger.With(zap.String("request_id", reqID))
			}

			rl := &reqLogger{logger: logger}
			ctx := context.WithValue(r.Context(), loggerKey{}, rl)

			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r.WithContext(ctx))

			rl.logger.Info("request",
				zap.Int("status", sw.status),
				zap.Duration("dur", time.Since(start)),
			)
		})
	}
}

// statusWriter wraps http.ResponseWriter to capture the status code.
// It also implements http.Hijacker so WebSocket upgrades work.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// zapRecoverer recovers from handler panics and logs the error and stack via
// the per-request zap logger, so the panic record carries the same
// method/path/ip/request_id fields as the access log. Mounted inside
// requestLogger; a stock chimw.Recoverer remains outside as a last-resort net
// for panics in the middleware above it.
func zapRecoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if err, ok := rec.(error); ok && err == http.ErrAbortHandler {
				panic(rec)
			}
			logFor(r).Error("panic recovered",
				zap.Any("err", rec),
				zap.ByteString("stack", debug.Stack()),
			)
			w.WriteHeader(http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// logFor returns the per-request logger from context.
func logFor(r *http.Request) *zap.Logger {
	if rl, ok := r.Context().Value(loggerKey{}).(*reqLogger); ok {
		return rl.logger
	}
	return zap.NewNop()
}

// identityLogger enriches the request logger with uid/email from JWT claims.
// Must run after auth.Middleware.
func identityLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims := auth.ClaimsFromContext(r.Context()); claims != nil {
			if rl, ok := r.Context().Value(loggerKey{}).(*reqLogger); ok {
				rl.logger = rl.logger.With(
					zap.String("uid", claims.Subject),
					zap.String("email", claims.Email),
				)
			}
		}
		next.ServeHTTP(w, r)
	})
}
