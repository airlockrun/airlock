package agentapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestStorageSubdomainAuthRequiresLiveOriginSession(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	agentID, userID := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	user, err := q.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	now := time.Now()
	session, err := q.CreateUserSession(ctx, dbq.CreateUserSessionParams{
		UserID:           user.ID,
		Kind:             "web",
		ClientName:       "storage test",
		DeviceName:       "storage test",
		RefreshTokenHash: []byte(uuid.NewString()),
		AuthenticatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
		ExpiresAt:        pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	token, err := auth.IssueSubdomainToken(testJWTSecret, agentID, userID, pgUUID(session.ID), user.Email, user.DisplayName, user.TenantRole, user.AuthEpoch)
	if err != nil {
		t.Fatalf("IssueSubdomainToken: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://agent.example.test/__air/storage/private/file", nil)
	req.AddCookie(&http.Cookie{Name: relayCookieName, Value: token})
	if _, ok := validateSubdomainAuth(req, q, testJWTSecret, agentID); !ok {
		t.Fatal("live subdomain session was rejected")
	}
	if rows, err := q.RevokeUserSessionByID(ctx, dbq.RevokeUserSessionByIDParams{ID: session.ID, UserID: user.ID}); err != nil || rows != 1 {
		t.Fatalf("RevokeUserSessionByID = (%d, %v)", rows, err)
	}
	if _, ok := validateSubdomainAuth(req, q, testJWTSecret, agentID); ok {
		t.Fatal("storage subdomain session survived per-session revoke")
	}
}
