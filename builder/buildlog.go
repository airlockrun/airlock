package builder

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// buildLog buffers Sol and Docker log lines in memory and flushes to DB periodically.
// A monotonic seq counter is assigned across both streams so the frontend can
// dedupe late WS messages against the REST snapshot (log_seq in agent_builds).
type buildLog struct {
	buildID pgtype.UUID
	q       *dbq.Queries
	logger  *zap.Logger

	mu     sync.Mutex
	sol    strings.Builder
	docker strings.Builder
	seq    int64
	dirty  bool

	done chan struct{}
}

// newBuildLog creates a buildLog and starts a background flush goroutine.
func newBuildLog(q *dbq.Queries, buildID pgtype.UUID, logger *zap.Logger) *buildLog {
	bl := &buildLog{
		buildID: buildID,
		q:       q,
		logger:  logger,
		done:    make(chan struct{}),
	}
	go bl.flushLoop()
	return bl
}

// appendSol records a Sol log line and returns its assigned sequence number.
func (bl *buildLog) appendSol(line string) int64 {
	bl.mu.Lock()
	bl.sol.WriteString(line)
	bl.sol.WriteByte('\n')
	bl.seq++
	seq := bl.seq
	bl.dirty = true
	bl.mu.Unlock()
	return seq
}

// appendDocker records a Docker log line and returns its assigned sequence number.
func (bl *buildLog) appendDocker(line string) int64 {
	bl.mu.Lock()
	bl.docker.WriteString(line)
	bl.docker.WriteByte('\n')
	bl.seq++
	seq := bl.seq
	bl.dirty = true
	bl.mu.Unlock()
	return seq
}

func (bl *buildLog) flush() {
	bl.mu.Lock()
	if !bl.dirty {
		bl.mu.Unlock()
		return
	}
	sol := bl.sol.String()
	docker := bl.docker.String()
	seq := bl.seq
	bl.dirty = false
	bl.mu.Unlock()

	if err := bl.q.UpdateAgentBuildLogs(context.Background(), dbq.UpdateAgentBuildLogsParams{
		ID:        bl.buildID,
		SolLog:    sol,
		DockerLog: docker,
		LogSeq:    seq,
	}); err != nil {
		bl.logger.Warn("flush build log", zap.Error(err))
	}
}

func (bl *buildLog) flushLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			bl.flush()
		case <-bl.done:
			return
		}
	}
}

func (bl *buildLog) close() {
	close(bl.done)
	bl.flush()
}
