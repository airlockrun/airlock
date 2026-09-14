package execution

import (
	"context"
	"errors"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

// Watch stops in-flight I/O on any failed live resolution. Only authoritative
// revocation requests durable job cancellation; lease recovery owns retries.
// Its goroutine holds no coordination state; the database is authoritative.
func Watch(ctx context.Context, q *dbq.Queries, agentID, runID uuid.UUID, cancel context.CancelFunc) func() {
	if q == nil || cancel == nil || agentID == uuid.Nil || runID == uuid.Nil {
		panic("execution: watch requires run coordinates, queries and cancellation")
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				check, end := context.WithTimeout(ctx, 5*time.Second)
				run, err := q.GetRunByIDAndAgent(check, dbq.GetRunByIDAndAgentParams{ID: pgID(runID), AgentID: pgID(agentID)})
				if err == nil && run.Status == "success" && run.ExecutionKind != string(Agent) {
					end()
					return
				}
				if err == nil {
					_, err = Resolve(check, q, agentID, runID)
				}
				end()
				if err != nil {
					cancel()
					if errors.Is(err, auth.ErrRunAuthorityRevoked) {
						cleanup, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
						_, _ = q.CancelExecutionJob(cleanup, pgID(runID))
						end()
					}
					return
				}
			}
		}
	}()
	return func() { close(stop); <-done }
}
