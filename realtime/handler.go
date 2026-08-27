package realtime

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

// Handler routes dynamic WebSocket subscriptions that require narrower access
// than the agent topics installed by the WS upgrade handler.
type Handler struct {
	db     *db.DB
	hub    *Hub
	pubsub *PubSub
	logger *zap.Logger
}

// NewHandler creates a new inbound message handler.
func NewHandler(database *db.DB, hub *Hub, pubsub *PubSub, logger *zap.Logger) *Handler {
	return &Handler{
		db:     database,
		hub:    hub,
		pubsub: pubsub,
		logger: logger,
	}
}

// HandleMessage routes an inbound client message.
func (h *Handler) HandleMessage(conn *Conn, env Envelope) {
	switch env.Type {
	case "subscribe.build":
		h.handleSubscribeBuild(conn, env)
	case "unsubscribe.build":
		h.handleUnsubscribeBuild(conn, env)
	case "subscribe.jobs":
		h.handleSubscribeJobs(conn, env)
	case "unsubscribe.jobs":
		h.handleUnsubscribeJobs(conn, env)
	default:
		conn.logger.Info("ws recv (rejected)", zap.String("type", env.Type))
		conn.SendEnvelope(errorEnvelope(env.RequestID, "unexpected message type: "+env.Type))
	}
}

// handleSubscribeBuild subscribes the connection to a build's verbose topic
// after checking the caller may view the owning agent's builds. The topic is
// keyed by the build UUID; the Build page sends this on mount.
func (h *Handler) handleSubscribeBuild(conn *Conn, env Envelope) {
	var req airlockv1.SubscribeBuildRequest
	if err := protojson.Unmarshal(env.Payload, &req); err != nil {
		conn.SendEnvelope(errorEnvelope(env.RequestID, "invalid subscribe.build payload"))
		return
	}
	buildID, err := uuid.Parse(req.BuildId)
	if err != nil {
		conn.SendEnvelope(errorEnvelope(env.RequestID, "invalid build id"))
		return
	}

	ctx := context.Background()
	q := dbq.New(h.db.Pool())
	// Plumbing lookup to resolve build→agent; the actual gate is the
	// authz.Authorize(AgentBuildsView) call below.
	build, err := q.GetAgentBuild(ctx, pgtype.UUID{Bytes: buildID, Valid: true})
	if err != nil {
		conn.SendEnvelope(errorEnvelope(env.RequestID, "build not found"))
		return
	}
	agentID, err := uuid.FromBytes(build.AgentID.Bytes[:])
	if err != nil {
		conn.SendEnvelope(errorEnvelope(env.RequestID, "build not found"))
		return
	}

	p := authz.UserPrincipal(conn.UserID, conn.TenantRole)
	if err := authz.Authorize(ctx, q, p, authz.AgentBuildsView, agentID); err != nil {
		conn.SendEnvelope(errorEnvelope(env.RequestID, "forbidden"))
		return
	}

	h.hub.Subscribe(conn, buildID)
}

// handleUnsubscribeBuild drops a per-build subscription (sent on unmount).
// No authz needed — leaving a topic is always allowed.
func (h *Handler) handleUnsubscribeBuild(conn *Conn, env Envelope) {
	var req airlockv1.UnsubscribeBuildRequest
	if err := protojson.Unmarshal(env.Payload, &req); err != nil {
		return
	}
	buildID, err := uuid.Parse(req.BuildId)
	if err != nil {
		return
	}
	h.hub.Unsubscribe(conn, buildID)
}

func (h *Handler) handleSubscribeJobs(conn *Conn, env Envelope) {
	var req airlockv1.SubscribeJobsRequest
	if err := protojson.Unmarshal(env.Payload, &req); err != nil {
		conn.SendEnvelope(errorEnvelope(env.RequestID, "invalid subscribe.jobs payload"))
		return
	}
	agentID, err := uuid.Parse(req.AgentId)
	if err != nil {
		conn.SendEnvelope(errorEnvelope(env.RequestID, "invalid agent id"))
		return
	}

	ctx := context.Background()
	q := dbq.New(h.db.Pool())
	p := authz.UserPrincipal(conn.UserID, conn.TenantRole)
	if err := authz.Authorize(ctx, q, p, authz.AgentJobView, agentID); err != nil {
		conn.SendEnvelope(errorEnvelope(env.RequestID, "forbidden"))
		return
	}

	conn.TrackJobsSubscription(agentID)
	topicID := JobsTopic(agentID)
	h.hub.Subscribe(conn, topicID)
	ack := NewEnvelope("jobs.subscribed", topicID.String(), &airlockv1.JobsSubscribedEvent{AgentId: agentID.String()})
	ack.RequestID = env.RequestID
	conn.SendEnvelope(ack)
}

// Leaving a topic is always allowed, including after access has been revoked.
func (h *Handler) handleUnsubscribeJobs(conn *Conn, env Envelope) {
	var req airlockv1.UnsubscribeJobsRequest
	if err := protojson.Unmarshal(env.Payload, &req); err != nil {
		return
	}
	agentID, err := uuid.Parse(req.AgentId)
	if err != nil {
		return
	}
	conn.UntrackJobsSubscription(agentID)
	h.hub.Unsubscribe(conn, JobsTopic(agentID))
}
