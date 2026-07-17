package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/realtime"
	"github.com/coder/websocket"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestWebSocketRejectsQueryTokenAndBadOrigin(t *testing.T) {
	h := NewWSHandler(nil, nil, nil, testJWTSecret, "https://example.test", zap.NewNop())
	tests := []struct {
		name   string
		target string
		origin string
		want   int
	}{
		{name: "query token", target: "/ws?token=secret", origin: "https://example.test", want: http.StatusBadRequest},
		{name: "missing origin", target: "/ws", want: http.StatusForbidden},
		{name: "wrong origin", target: "/ws", origin: "https://evil.test", want: http.StatusForbidden},
		{name: "missing cookie", target: "/ws", origin: "https://example.test", want: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.Header.Set("Origin", tt.origin)
			rec := httptest.NewRecorder()
			h.Upgrade(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestEstablishedWebSocketClosesOnLiveAuthorizationRevocation(t *testing.T) {
	skipIfNoDB(t)
	q := dbq.New(testDB.Pool())
	ctx := context.Background()

	type testSession struct {
		user    dbq.User
		token   string
		claims  *auth.Claims
		conn    *websocket.Conn
		cleanup func()
	}
	newSession := func(name string) testSession {
		user, err := q.CreateUser(ctx, dbq.CreateUserParams{
			Email:       name + "-" + uuid.NewString() + "@example.com",
			DisplayName: name,
			TenantRole:  "user",
		})
		if err != nil {
			t.Fatal(err)
		}
		token, _, err := issueUserSessionTokens(ctx, testDB, testJWTSecret, user, userSessionKindWeb, webClientName, "test")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := auth.ValidateUserAccessToken(testJWTSecret, token)
		if err != nil {
			t.Fatal(err)
		}
		conn, cleanup := dialMonitoredWebSocket(t, token)
		return testSession{user: user, token: token, claims: claims, conn: conn, cleanup: cleanup}
	}

	sessionRevoked := newSession("session-revoked")
	defer sessionRevoked.cleanup()
	if _, err := q.RevokeUserSessionByID(ctx, dbq.RevokeUserSessionByIDParams{
		ID:     toPgUUID(uuid.MustParse(sessionRevoked.claims.SessionID)),
		UserID: sessionRevoked.user.ID,
	}); err != nil {
		t.Fatal(err)
	}
	awaitWebSocketClosed(t, sessionRevoked.conn)

	userDeleted := newSession("user-deleted")
	defer userDeleted.cleanup()
	if err := q.DeleteUser(ctx, userDeleted.user.ID); err != nil {
		t.Fatal(err)
	}
	awaitWebSocketClosed(t, userDeleted.conn)

	epochRevoked := newSession("epoch-revoked")
	defer epochRevoked.cleanup()
	if err := q.UpdateUserRole(ctx, dbq.UpdateUserRoleParams{ID: epochRevoked.user.ID, TenantRole: "manager"}); err != nil {
		t.Fatal(err)
	}
	awaitWebSocketClosed(t, epochRevoked.conn)
}

func TestEstablishedWebSocketClosesWhenMembershipChanges(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	user, err := q.GetUserByID(context.Background(), toPgUUID(userID))
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := issueUserSessionTokens(context.Background(), testDB, testJWTSecret, user, userSessionKindWeb, webClientName, "test")
	if err != nil {
		t.Fatal(err)
	}
	conn, cleanup := dialMonitoredWebSocket(t, token)
	defer cleanup()
	if err := q.UpsertAgentGrant(context.Background(), dbq.UpsertAgentGrantParams{
		AgentID: toPgUUID(agentID), GranteeID: toPgUUID(userID), Role: "user",
	}); err != nil {
		t.Fatal(err)
	}
	awaitWebSocketClosed(t, conn)
}

func TestEstablishedWebSocketClosesAtAccessExpiry(t *testing.T) {
	skipIfNoDB(t)
	q := dbq.New(testDB.Pool())
	user, err := q.CreateUser(context.Background(), dbq.CreateUserParams{
		Email:       "ws-expiry-" + uuid.NewString() + "@example.com",
		DisplayName: "Expiry User",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := issueUserSessionTokens(context.Background(), testDB, testJWTSecret, user, userSessionKindWeb, webClientName, "test")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := auth.ValidateUserAccessToken(testJWTSecret, token)
	if err != nil {
		t.Fatal(err)
	}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Second))
	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	conn, cleanup := dialMonitoredWebSocket(t, token)
	defer cleanup()
	awaitWebSocketClosed(t, conn)
}

func dialMonitoredWebSocket(t *testing.T, token string) (*websocket.Conn, func()) {
	t.Helper()
	logger := zap.NewNop()
	hub := realtime.NewHub(logger)
	realtimeHandler := realtime.NewHandler(testDB, hub, nil, logger)
	var wsHandler *WSHandler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wsHandler.Upgrade(w, r)
	}))
	wsHandler = NewWSHandler(testDB, hub, realtimeHandler, testJWTSecret, server.URL, logger)
	wsHandler.pollEvery = 20 * time.Millisecond

	header := http.Header{}
	header.Set("Origin", server.URL)
	header.Set("Cookie", accessCookieName+"="+token)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/ws", &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		server.Close()
		if response != nil {
			t.Fatalf("dial websocket: %v (status %d)", err, response.StatusCode)
		}
		t.Fatalf("dial websocket: %v", err)
	}
	cleanup := func() {
		_ = conn.Close(websocket.StatusNormalClosure, "test cleanup")
		server.Close()
	}
	return conn, cleanup
}

func awaitWebSocketClosed(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_, _, err := conn.Read(ctx)
	if err == nil {
		t.Fatal("websocket read succeeded, want closed connection")
	}
	if ctx.Err() != nil {
		t.Fatalf("websocket did not close promptly: %v", err)
	}
}
