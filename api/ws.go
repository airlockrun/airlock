package api

import (
	"context"
	"net/http"

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
// WebSocket, and auto-subscribes the connection to every agent the user has
// access to (via agent_members). The client does not issue subscribe
// messages; authorization is enforced at connect time from durable DB state.
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
	memberAgents, err := q.ListAgentIDsByMember(r.Context(), toPgUUID(userID))
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
	h.hub.Register(conn)
	for _, pgID := range memberAgents {
		agentID, err := uuid.FromBytes(pgID.Bytes[:])
		if err != nil {
			continue
		}
		h.hub.Subscribe(conn, agentID)
	}
	h.logger.Info("ws connected",
		zap.String("conn", conn.ID),
		zap.String("uid", userID.String()),
		zap.String("email", claims.Email),
		zap.String("ip", r.RemoteAddr),
		zap.Int("topics", len(memberAgents)),
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
