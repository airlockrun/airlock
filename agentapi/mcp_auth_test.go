package agentapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestResolvePrincipalStrictTokenProfiles(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	targetAgentID, userID := testAgentAndUser(t)
	if err := q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{ID: toPgUUID(targetAgentID), Status: "active", ErrorMessage: ""}); err != nil {
		t.Fatalf("activate target agent: %v", err)
	}
	publicURL := "https://airlock.example.test"
	audience := publicURL + "/api/agent/" + targetAgentID.String() + "/mcp"
	if _, err := q.CreateOAuthClient(ctx, dbq.CreateOAuthClientParams{
		ClientID: "test-client", ClientName: "Test", RedirectUris: []string{"http://localhost/callback"},
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		TokenEndpointAuthMethod: "none", Scope: "mcp",
	}); err != nil {
		t.Fatalf("CreateOAuthClient: %v", err)
	}
	if err := q.UpsertGrant(ctx, dbq.UpsertGrantParams{
		UserID: toPgUUID(userID), ClientID: "test-client", AgentID: toPgUUID(targetAgentID), Scope: "mcp",
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatalf("UpsertGrant: %v", err)
	}

	userToken, userSession := issueMCPUserToken(t, q, userID, false)
	oauthToken, _ := auth.IssueOAuthAccessToken(testJWTSecret, userID, "user@example.com", "user", "test-client", "mcp", audience, 0)
	wrongAudienceToken, _ := auth.IssueOAuthAccessToken(testJWTSecret, userID, "user@example.com", "user", "test-client", "mcp", audience+"/other", 0)
	agentToken, _ := auth.IssueAgentToken(testJWTSecret, targetAgentID, 1)
	subdomainToken, _ := auth.IssueSubdomainToken(testJWTSecret, targetAgentID, userID, uuid.New(), "user@example.com", "User", "user", 0)
	missingSessionToken, _ := auth.IssueToken(testJWTSecret, userID, "user@example.com", "User", "user", false)

	request := func(token string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}
	principal, err := resolvePrincipal(ctx, request(userToken), q, testJWTSecret, targetAgentID, publicURL)
	if err != nil || principal.Kind != MCPPrincipalUser {
		t.Fatalf("user principal = %+v, err = %v", principal, err)
	}
	principal, err = resolvePrincipal(ctx, request(oauthToken), q, testJWTSecret, targetAgentID, publicURL)
	if err != nil || principal.Kind != MCPPrincipalOAuthClient || principal.ClientID != "test-client" {
		t.Fatalf("OAuth principal = %+v, err = %v", principal, err)
	}
	if _, err := resolvePrincipal(ctx, request(wrongAudienceToken), q, testJWTSecret, targetAgentID, publicURL); !errors.Is(err, errAudienceMismatch) {
		t.Fatalf("wrong-audience OAuth error = %v, want errAudienceMismatch", err)
	}
	if _, err := resolvePrincipal(ctx, request(agentToken), q, testJWTSecret, targetAgentID, publicURL); err == nil || err.Error() != "agent JWT requires X-Run-ID header" {
		t.Fatalf("agent profile error = %v, want X-Run-ID requirement", err)
	}
	if _, err := resolvePrincipal(ctx, request(subdomainToken), q, testJWTSecret, targetAgentID, publicURL); !errors.Is(err, errInvalidToken) {
		t.Fatalf("subdomain token error = %v, want errInvalidToken", err)
	}
	if _, err := resolvePrincipal(ctx, request(missingSessionToken), q, testJWTSecret, targetAgentID, publicURL); !errors.Is(err, errInvalidToken) {
		t.Fatalf("missing-session user token error = %v, want errInvalidToken", err)
	}
	if rows, err := q.RevokeUserSessionByID(ctx, dbq.RevokeUserSessionByIDParams{ID: userSession.ID, UserID: toPgUUID(userID)}); err != nil || rows != 1 {
		t.Fatalf("revoke user session = (%d, %v), want (1, nil)", rows, err)
	}
	if _, err := resolvePrincipal(ctx, request(userToken), q, testJWTSecret, targetAgentID, publicURL); !errors.Is(err, errInvalidToken) {
		t.Fatalf("revoked-session user token error = %v, want errInvalidToken", err)
	}
	liveUserToken, _ := issueMCPUserToken(t, q, userID, false)
	if _, err := testDB.Pool().Exec(ctx, `UPDATE oauth_grants SET revoked_at = now() WHERE user_id = $1 AND client_id = $2 AND agent_id = $3`, userID, "test-client", targetAgentID); err != nil {
		t.Fatalf("revoke OAuth grant: %v", err)
	}
	if _, err := resolvePrincipal(ctx, request(oauthToken), q, testJWTSecret, targetAgentID, publicURL); !errors.Is(err, errClientRevoked) {
		t.Fatalf("revoked-grant OAuth error = %v, want errClientRevoked", err)
	}
	if err := q.UpsertGrant(ctx, dbq.UpsertGrantParams{
		UserID: toPgUUID(userID), ClientID: "test-client", AgentID: toPgUUID(targetAgentID), Scope: "mcp",
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatalf("restore grant: %v", err)
	}
	if _, err := testDB.Pool().Exec(ctx, `UPDATE users SET auth_epoch = auth_epoch + 1 WHERE id = $1`, userID); err != nil {
		t.Fatalf("advance auth epoch: %v", err)
	}
	if _, err := resolvePrincipal(ctx, request(oauthToken), q, testJWTSecret, targetAgentID, publicURL); !errors.Is(err, errInvalidToken) {
		t.Fatalf("stale-epoch OAuth error = %v, want errInvalidToken", err)
	}
	if _, err := resolvePrincipal(ctx, request(liveUserToken), q, testJWTSecret, targetAgentID, publicURL); !errors.Is(err, errInvalidToken) {
		t.Fatalf("stale-epoch user error = %v, want errInvalidToken", err)
	}
	if _, err := testDB.Pool().Exec(ctx, `UPDATE users SET must_change_password = true WHERE id = $1`, userID); err != nil {
		t.Fatalf("require password change: %v", err)
	}
	forcedUserToken, _ := issueMCPUserToken(t, q, userID, false)
	if _, err := resolvePrincipal(ctx, request(forcedUserToken), q, testJWTSecret, targetAgentID, publicURL); !errors.Is(err, errInvalidToken) {
		t.Fatalf("live forced-change user token error = %v, want errInvalidToken", err)
	}
}

func issueMCPUserToken(t *testing.T, q *dbq.Queries, userID uuid.UUID, mustChangeClaim bool) (string, dbq.UserSession) {
	t.Helper()
	ctx := context.Background()
	user, err := q.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	now := time.Now()
	session, err := q.CreateUserSession(ctx, dbq.CreateUserSessionParams{
		UserID: user.ID, Kind: "web", ClientName: "mcp-test", DeviceName: "mcp-test",
		RefreshTokenHash: []byte(uuid.NewString()),
		AuthenticatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
		ExpiresAt:        pgtype.Timestamptz{Time: now.Add(auth.RefreshTokenDuration), Valid: true},
	})
	if err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	token, err := auth.IssueUserAccessToken(testJWTSecret, userID, user.Email, user.DisplayName, user.TenantRole, mustChangeClaim, pgUUID(session.ID), user.AuthEpoch, now)
	if err != nil {
		t.Fatalf("IssueUserAccessToken: %v", err)
	}
	return token, session
}

func TestResolvePrincipalRequiresRunningAgentParent(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	callerID, userID := testAgentAndUser(t)
	targetID, _ := testAgentAndUser(t)
	if err := q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{ID: toPgUUID(callerID), Status: "active", ErrorMessage: ""}); err != nil {
		t.Fatalf("activate caller agent: %v", err)
	}
	conv, err := q.CreateWebConversation(ctx, dbq.CreateWebConversationParams{
		AgentID: toPgUUID(callerID), UserID: toPgUUID(userID), Title: "parent",
	})
	if err != nil {
		t.Fatalf("CreateWebConversation: %v", err)
	}
	run := createTestRun(t, callerID, pgtype.UUID{}, "prompt", pgUUID(conv.ID).String())
	token, err := auth.IssueAgentToken(testJWTSecret, callerID, 1)
	if err != nil {
		t.Fatalf("IssueAgentToken: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Run-ID", pgUUID(run.ID).String())
	principal, err := resolvePrincipal(ctx, req, q, testJWTSecret, targetID, "https://airlock.example.test")
	if err != nil || principal.ParentRunID != pgUUID(run.ID) {
		t.Fatalf("running parent principal = %+v, err = %v", principal, err)
	}
	if _, err := testDB.Pool().Exec(ctx, `UPDATE runs SET status = 'success' WHERE id = $1`, run.ID); err != nil {
		t.Fatalf("complete parent: %v", err)
	}
	if _, err := resolvePrincipal(ctx, req, q, testJWTSecret, targetID, "https://airlock.example.test"); err == nil {
		t.Fatal("terminal parent run accepted for A2A")
	}
}
