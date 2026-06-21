package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/realtime"
	"github.com/coder/websocket"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// WSHandler upgrades HTTP connections to WebSocket.
type WSHandler struct {
	db        *db.DB
	hub       *realtime.Hub
	handler   *realtime.Handler
	jwtSecret string
	logger    *zap.Logger
}

// NewWSHandler creates a new WebSocket upgrade handler.
func NewWSHandler(database *db.DB, hub *realtime.Hub, handler *realtime.Handler, jwtSecret string, logger *zap.Logger) *WSHandler {
	return &WSHandler{db: database, hub: hub, handler: handler, jwtSecret: jwtSecret, logger: logger}
}

// Upgrade handles GET /ws?token=<jwt> — validates the token, upgrades to
// WebSocket, and auto-subscribes the connection to every agent the user holds
// an explicit per-user grant on (via agent_grants). The client does not issue
// subscribe messages; authorization is enforced at connect time from durable
// DB state.
func (h *WSHandler) Upgrade(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing token")
		return
	}

	claims, err := auth.ValidateToken(h.jwtSecret, token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token claims")
		return
	}

	// Resolve the user's member agents BEFORE the upgrade so a DB error can
	// return a real HTTP status instead of a half-open socket.
	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: pure read of caller's own grant rows; no authz decision to gate (you can always see what you're a member of)
	memberAgents, err := q.ListAgentIDsByGrantee(r.Context(), toPgUUID(userID))
	if err != nil {
		h.logger.Error("list member agents for ws", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to resolve agent membership")
		return
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // CORS handled at middleware level
	})
	if err != nil {
		h.logger.Error("upgrade failed", zap.Error(err))
		return
	}

	conn := realtime.NewConn(ws, userID, claims.Email, h.logger)
	// Replay cursor: max Envelope.Seq the client already processed.
	// Absent/garbage → 0 → fresh connect, no replay (the client's
	// normal initial DB load covers it). Must be set before Subscribe.
	conn.SinceSeq, _ = strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	h.hub.Register(conn)
	for _, pgID := range memberAgents {
		agentID, err := uuid.FromBytes(pgID.Bytes[:])
		if err != nil {
			continue
		}
		h.hub.Subscribe(conn, agentID)
	}
	// Also subscribe the connection to the user's own UUID as a topic
	// — sysagent publishes thread events here (one user topic carries
	// every thread's events, with the thread id on envelope.ConversationID
	// for client-side per-thread routing). This avoids a dynamic
	// subscribe roundtrip when the user creates a fresh thread mid-session.
	h.hub.Subscribe(conn, userID)
	h.logger.Info("ws connected",
		zap.String("conn", conn.ID),
		zap.String("uid", userID.String()),
		zap.String("email", claims.Email),
		zap.String("ip", r.RemoteAddr),
		zap.Int("topics", len(memberAgents)+1),
	)

	// Use background context — r.Context() is cancelled when the handler returns,
	// but the WebSocket connection outlives the HTTP handler.
	ctx := context.Background()

	go conn.WritePump(ctx)
	go func() {
		conn.ReadPump(ctx, h.handler.HandleMessage)
		h.hub.Unregister(conn)
		conn.Close()
		h.logger.Info("ws disconnected", zap.String("conn", conn.ID))
	}()
}
