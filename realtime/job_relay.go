package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const jobEventsChannel = "airlock_job_events"

var jobsTopicNamespace = uuid.MustParse("a160366a-647d-5f0e-8d20-5cac99dbe4ec")

// JobsTopic derives the private operator topic for an agent's job events.
func JobsTopic(agentID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(jobsTopicNamespace, agentID[:])
}

type jobNotification struct {
	Kind         string    `json:"kind"`
	AgentID      uuid.UUID `json:"agent_id"`
	JobID        uuid.UUID `json:"job_id"`
	StateVersion int64     `json:"state_version"`
}

type jobLoader interface {
	GetAgentJobByID(context.Context, pgtype.UUID) (dbq.AgentJob, error)
}

// JobEventRelay fans committed PostgreSQL job notifications out to this
// replica's local WebSocket subscribers.
type JobEventRelay struct {
	pool   *pgxpool.Pool
	hub    *Hub
	logger *zap.Logger
}

func NewJobEventRelay(pool *pgxpool.Pool, hub *Hub, logger *zap.Logger) *JobEventRelay {
	if pool == nil {
		panic("realtime: nil job event relay pool")
	}
	if hub == nil {
		panic("realtime: nil job event relay hub")
	}
	if logger == nil {
		panic("realtime: nil job event relay logger")
	}
	return &JobEventRelay{pool: pool, hub: hub, logger: logger}
}

// Run maintains a dedicated LISTEN connection until ctx is cancelled.
func (r *JobEventRelay) Run(ctx context.Context) error {
	for {
		if err := r.listen(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) {
			r.logger.Error("job event listener disconnected", zap.Error(err))
		}
		if ctx.Err() != nil {
			return nil
		}

		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (r *JobEventRelay) listen(ctx context.Context) error {
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := conn.Exec(cleanupCtx, "UNLISTEN "+jobEventsChannel); err != nil {
			_ = conn.Conn().Close(cleanupCtx)
		}
		conn.Release()
	}()

	if _, err := conn.Exec(ctx, "LISTEN "+jobEventsChannel); err != nil {
		return err
	}
	r.hub.ResyncAll()
	queries := dbq.New(conn)
	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		r.handleNotification(ctx, queries, notification.Payload)
	}
}

func (r *JobEventRelay) handleNotification(ctx context.Context, loader jobLoader, payload string) {
	var notification jobNotification
	if err := json.Unmarshal([]byte(payload), &notification); err != nil {
		r.logger.Warn("invalid job event notification", zap.Error(err))
		return
	}
	if (notification.Kind != "progress" && notification.Kind != "lifecycle") ||
		notification.AgentID == uuid.Nil || notification.JobID == uuid.Nil || notification.StateVersion < 1 {
		r.logger.Warn("invalid job event notification fields")
		return
	}

	job, err := loader.GetAgentJobByID(ctx, pgtype.UUID{Bytes: notification.JobID, Valid: true})
	if err != nil {
		r.logger.Error("load job for realtime event", zap.String("job_id", notification.JobID.String()), zap.Error(err))
		return
	}
	if !job.AgentID.Valid || uuid.UUID(job.AgentID.Bytes) != notification.AgentID ||
		!job.ID.Valid || uuid.UUID(job.ID.Bytes) != notification.JobID {
		r.logger.Error("job event notification does not match loaded job", zap.String("job_id", notification.JobID.String()))
		return
	}
	if job.StateVersion < notification.StateVersion {
		r.logger.Debug("discarding job event notification ahead of loaded row",
			zap.String("job_id", notification.JobID.String()),
			zap.Int64("notified_state_version", notification.StateVersion),
			zap.Int64("current_state_version", job.StateVersion))
		return
	}

	topicID := JobsTopic(notification.AgentID)
	var env Envelope
	if notification.Kind == "progress" && job.StateVersion == notification.StateVersion {
		env = NewEnvelope("job.progress", topicID.String(), &airlockv1.JobProgressEvent{
			AgentId:      notification.AgentID.String(),
			JobId:        notification.JobID.String(),
			StateVersion: job.StateVersion,
			Progress:     convert.JobProgressToProto(job),
		})
	} else {
		env = NewEnvelope("job.lifecycle", topicID.String(), &airlockv1.JobLifecycleEvent{
			Summary: convert.JobToProto(job, false),
		})
	}
	r.hub.BroadcastToTopic(topicID, env)
}
