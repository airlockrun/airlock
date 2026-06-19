package realtime

import (
	"context"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

// Handler routes inbound WebSocket messages. The WS upgrade handler
// auto-subscribes new connections to every agent the user is a member of, so
// the only inbound messages we accept are dynamic per-build subscriptions for
// the Build page (which we don't want streaming to every member by default).
// Anything else is logged and rejected.
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

	// AgentBuildsView is agent-axis (resolved from agent_members), so an empty
	// tenant role is fine here — only membership grants build visibility.
	p := authz.UserPrincipal(conn.UserID, auth.Role(""))
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
