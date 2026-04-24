package attachref

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/storage"
	"go.uber.org/zap"
)

// ScheduleDelete fires-and-forgets S3 DeleteObject calls for the given keys.
// Runs in a detached goroutine with a context that outlives the request
// (WithoutCancel + 30s deadline per key) so an HTTP request completing
// doesn't abort mid-cleanup.
//
// Errors are logged; they do not propagate back to the caller. This matches
// the inline-goroutine pattern used by airlock's other background work
// (see cmd/airlock/main.go event cleanup).
func ScheduleDelete(ctx context.Context, s3 *storage.S3Client, logger *zap.Logger, keys []string) {
	if len(keys) == 0 {
		return
	}
	// Copy the slice — caller may mutate it after we return.
	ks := make([]string, len(keys))
	copy(ks, keys)

	detached := context.WithoutCancel(ctx)
	go func() {
		for _, key := range ks {
			kctx, cancel := context.WithTimeout(detached, 30*time.Second)
			if err := s3.DeleteObject(kctx, key); err != nil {
				logger.Error("attachref: delete failed",
					zap.String("key", key),
					zap.Error(err),
				)
			}
			cancel()
		}
	}()
}
