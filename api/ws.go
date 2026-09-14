package api

import (
	"context"
	"maps"
	"net/http"
	"strconv"
	"time"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/service/accounts"
	agentsservice "github.com/airlockrun/airlock/service/agents"
	jobservice "github.com/airlockrun/airlock/service/jobs"
	"github.com/coder/websocket"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const wsAuthorizationPollInterval = 2 * time.Second

// WSHandler upgrades HTTP connections to WebSocket.
type WSHandler struct {
	db        *db.DB
	hub       *realtime.Hub
	handler   *realtime.Handler
	jwtSecret string
	publicURL string
	logger    *zap.Logger
	pollEvery time.Duration
}

// NewWSHandler creates a new WebSocket upgrade handler.
func NewWSHandler(database *db.DB, hub *realtime.Hub, handler *realtime.Handler, jwtSecret, publicURL string, logger *zap.Logger) *WSHandler {
	return &WSHandler{db: database, hub: hub, handler: handler, jwtSecret: jwtSecret, publicURL: publicURL, logger: logger, pollEvery: wsAuthorizationPollInterval}
}

type wsMemberships map[uuid.UUID]string

// Upgrade handles GET /ws using the HttpOnly access cookie, upgrades to
// WebSocket, and auto-subscribes the connection to every agent the user holds
// an explicit per-user grant on (via agent_grants). Narrower topics are added
// through authorized control messages; a DB-backed monitor closes the
// connection when authorization or memberships change.
func (h *WSHandler) Upgrade(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != configuredOrigin(h.publicURL) {
		writeError(w, http.StatusForbidden, "bad origin")
		return
	}
	if r.URL.Query().Has("token") {
		writeError(w, http.StatusBadRequest, "query token authentication is not supported")
		return
	}
	cookie, err := auth.UniqueCookie(r, accessCookieName)
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusUnauthorized, "missing access cookie")
		return
	}

	claims, err := auth.ValidateUserAccessToken(h.jwtSecret, cookie.Value)
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
	claims, err = auth.ResolveLiveUserClaims(r.Context(), q, claims, true)
	if err != nil || claims.MustChangePassword {
		writeError(w, http.StatusUnauthorized, "invalid or revoked session")
		return
	}
	memberships, err := accounts.Subscriptions(r.Context(), q, authz.PrincipalFromClaims(claims))
	if err != nil {
		h.logger.Error("list member agents for ws", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to resolve agent membership")
		return
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // The exact Origin check above is authoritative.
	})
	if err != nil {
		h.logger.Error("upgrade failed", zap.Error(err))
		return
	}

	// Use background context because r.Context() is cancelled when the handler
	// returns, while the WebSocket connection remains active.
	ctx, cancel := context.WithDeadline(context.Background(), claims.ExpiresAt.Time)
	conn := realtime.NewConn(ws, userID, claims.Email, auth.Role(claims.TenantRole), cancel, h.logger)
	conn.Identity = claims.Identity()
	// Replay cursor: max Envelope.Seq the client already processed.
	// Absent/garbage → 0 → fresh connect, no replay (the client's
	// normal initial DB load covers it). Must be set before Subscribe.
	conn.SinceSeq, _ = strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	h.hub.Register(conn)
	for agentID := range memberships {
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
		zap.Int("topics", len(memberships)+1),
	)

	go conn.WritePump(ctx)
	go h.monitorAuthorization(ctx, cancel, conn, claims, userID, memberships)
	go func() {
		conn.ReadPump(ctx, h.handler.HandleMessage)
		cancel()
		h.hub.Unregister(conn)
		h.logger.Info("ws disconnected", zap.String("conn", conn.ID))
	}()
}

// NewRealtimeHandler wires dynamic subscriptions to their domain services.
func NewRealtimeHandler(database *db.DB, hub *realtime.Hub) *realtime.Handler {
	q := dbq.New(database.Pool())
	principal := func(ctx context.Context, conn *realtime.Conn) (authz.Principal, error) {
		claims, err := conn.Identity.Resolve(ctx, q)
		if err != nil {
			return authz.Principal{}, apperr.ErrUnauthorized
		}
		if err := auth.RequireSecuredAccount(claims); err != nil {
			return authz.Principal{}, err
		}
		p := authz.PrincipalFromClaims(claims)
		if p.UserID != conn.UserID {
			return authz.Principal{}, apperr.ErrUnauthorized
		}
		return p, nil
	}
	return realtime.NewHandler(hub, func(ctx context.Context, c *realtime.Conn, id uuid.UUID) error {
		p, err := principal(ctx, c)
		if err != nil {
			return err
		}
		return agentsservice.AuthorizeBuildSubscription(ctx, q, p, id)
	}, func(ctx context.Context, c *realtime.Conn, id uuid.UUID) error {
		p, err := principal(ctx, c)
		if err != nil {
			return err
		}
		return jobservice.AuthorizeSubscription(ctx, q, p, id)
	})
}

func (h *WSHandler) monitorAuthorization(ctx context.Context, cancel context.CancelFunc, conn *realtime.Conn, claims *auth.Claims, userID uuid.UUID, memberships wsMemberships) {
	ticker := time.NewTicker(h.pollEvery)
	defer ticker.Stop()
	q := dbq.New(h.db.Pool())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			live, err := auth.ResolveLiveUserClaims(ctx, q, claims, true)
			if err != nil || live.MustChangePassword {
				h.logger.Info("closing ws after session authorization changed", zap.String("uid", userID.String()), zap.Error(err))
				cancel()
				return
			}
			if auth.Role(live.TenantRole) != conn.TenantRole {
				h.logger.Info("closing ws after tenant role changed", zap.String("uid", userID.String()))
				cancel()
				return
			}
			p := authz.PrincipalFromClaims(live)
			current, err := accounts.Subscriptions(ctx, q, p)
			if err != nil || !maps.Equal(memberships, current) {
				h.logger.Info("closing ws after agent memberships changed", zap.String("uid", userID.String()), zap.Error(err))
				cancel()
				return
			}
			for _, agentID := range conn.JobsSubscriptions() {
				if err := jobservice.AuthorizeSubscription(ctx, q, p, agentID); err != nil {
					h.logger.Info("closing ws after jobs subscription authorization changed",
						zap.String("uid", userID.String()), zap.String("agent_id", agentID.String()), zap.Error(err))
					cancel()
					return
				}
			}
		}
	}
}
