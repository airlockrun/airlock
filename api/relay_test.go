package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestRelayCodePersistsHashAndBindsTarget(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	agent, err := dbq.New(testDB.Pool()).GetAgentByID(context.Background(), toPgUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	nonce, err := newRelaySecret()
	if err != nil {
		t.Fatalf("newRelaySecret: %v", err)
	}
	returnURL := "https://" + agent.Slug + ".agents.test/private?tab=one"
	response := generateRelayCode(t, userID, returnURL, nonce, "agents.test", "https://airlock.test")

	callback, err := url.Parse(response.CallbackUrl)
	if err != nil {
		t.Fatalf("parse callback URL: %v", err)
	}
	if callback.Query().Get("code") != response.Code {
		t.Fatalf("callback code does not match response")
	}
	var plaintextCodes int
	if err := testDB.Pool().QueryRow(context.Background(), `SELECT count(*) FROM relay_codes WHERE code_hash = convert_to($1, 'UTF8')`, response.Code).Scan(&plaintextCodes); err != nil {
		t.Fatalf("query plaintext relay code: %v", err)
	}
	if plaintextCodes != 0 {
		t.Fatal("relay code was persisted in plaintext")
	}
	row, err := dbq.New(testDB.Pool()).ConsumeRelayCode(context.Background(), hashToken(response.Code))
	if err != nil {
		t.Fatalf("ConsumeRelayCode: %v", err)
	}
	if pgUUID(row.AgentID) != agentID {
		t.Errorf("AgentID = %s, want %s", pgUUID(row.AgentID), agentID)
	}
	if row.TargetOrigin != "https://"+agent.Slug+".agents.test" {
		t.Errorf("TargetOrigin = %q", row.TargetOrigin)
	}
	if row.ReturnPath != "/private?tab=one" {
		t.Errorf("ReturnPath = %q", row.ReturnPath)
	}
	if !bytes.Equal(row.NonceHash, hashToken(nonce)) {
		t.Error("persisted nonce hash does not match")
	}
	if !row.SessionID.Valid {
		t.Fatal("relay code did not preserve the originating session")
	}
}

func TestRelayCodeIsSingleUse(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	agent, err := dbq.New(testDB.Pool()).GetAgentByID(context.Background(), toPgUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	nonce, _ := newRelaySecret()
	response := generateRelayCode(t, userID, "https://"+agent.Slug+".agents.test/private", nonce, "agents.test", "https://airlock.test")
	var originSessionID uuid.UUID
	if err := testDB.Pool().QueryRow(context.Background(), `SELECT session_id FROM relay_codes WHERE code_hash = $1`, hashToken(response.Code)).Scan(&originSessionID); err != nil {
		t.Fatalf("read relay origin session: %v", err)
	}

	first := relayCallbackRequest(t, response.CallbackUrl, nonce)
	firstRec := httptest.NewRecorder()
	handleRelayCallback(firstRec, first, testDB, testJWTSecret, agentID, zap.NewNop())
	if firstRec.Code != http.StatusFound {
		t.Fatalf("first callback status = %d, want %d; body: %s", firstRec.Code, http.StatusFound, firstRec.Body.String())
	}
	cookie := cookieByName(firstRec.Result().Cookies(), relayCookieName)
	if cookie == nil {
		t.Fatal("first callback did not issue a session cookie")
	}
	claims, err := auth.ValidateSubdomainToken(testJWTSecret, cookie.Value, agentID)
	if err != nil {
		t.Fatalf("ValidateSubdomainToken: %v", err)
	}
	if claims.SessionID != originSessionID.String() {
		t.Fatalf("subdomain sid = %q, want relay origin %q", claims.SessionID, originSessionID)
	}
	assertRelayNonceCleared(t, firstRec)

	second := relayCallbackRequest(t, response.CallbackUrl, nonce)
	secondRec := httptest.NewRecorder()
	handleRelayCallback(secondRec, second, testDB, testJWTSecret, agentID, zap.NewNop())
	if secondRec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed callback status = %d, want %d", secondRec.Code, http.StatusUnauthorized)
	}
	if cookieByName(secondRec.Result().Cookies(), relayCookieName) != nil {
		t.Fatal("replayed callback issued a session cookie")
	}
}

func TestRelayCodeExpires(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	agent, err := dbq.New(testDB.Pool()).GetAgentByID(context.Background(), toPgUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	nonce, _ := newRelaySecret()
	response := generateRelayCode(t, userID, "https://"+agent.Slug+".agents.test/", nonce, "agents.test", "https://airlock.test")
	if _, err := testDB.Pool().Exec(context.Background(), `UPDATE relay_codes SET expires_at = now() - interval '1 second' WHERE code_hash = $1`, hashToken(response.Code)); err != nil {
		t.Fatalf("expire relay code: %v", err)
	}

	req := relayCallbackRequest(t, response.CallbackUrl, nonce)
	rec := httptest.NewRecorder()
	handleRelayCallback(rec, req, testDB, testJWTSecret, agentID, zap.NewNop())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired callback status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if cookieByName(rec.Result().Cookies(), relayCookieName) != nil {
		t.Fatal("expired callback issued a session cookie")
	}
	assertRelayNonceCleared(t, rec)
}

func TestRelayCodeConcurrentConsumptionHasOneWinner(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	agent, err := dbq.New(testDB.Pool()).GetAgentByID(context.Background(), toPgUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	nonce, _ := newRelaySecret()
	response := generateRelayCode(t, userID, "https://"+agent.Slug+".agents.test/", nonce, "agents.test", "https://airlock.test")

	start := make(chan struct{})
	statuses := make(chan int, 2)
	requests := []*http.Request{
		relayCallbackRequest(t, response.CallbackUrl, nonce),
		relayCallbackRequest(t, response.CallbackUrl, nonce),
	}
	for _, req := range requests {
		go func(req *http.Request) {
			<-start
			rec := httptest.NewRecorder()
			handleRelayCallback(rec, req, testDB, testJWTSecret, agentID, zap.NewNop())
			statuses <- rec.Code
		}(req)
	}
	close(start)
	winners := 0
	rejected := 0
	for range 2 {
		switch <-statuses {
		case http.StatusFound:
			winners++
		case http.StatusUnauthorized:
			rejected++
		}
	}
	if winners != 1 || rejected != 1 {
		t.Fatalf("concurrent callbacks: success=%d unauthorized=%d, want 1 each", winners, rejected)
	}
}

func TestRelayCallbackRejectsRevokedOriginSession(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	agent, err := q.GetAgentByID(context.Background(), toPgUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	nonce, _ := newRelaySecret()
	response := generateRelayCode(t, userID, "https://"+agent.Slug+".agents.test/private", nonce, "agents.test", "https://airlock.test")
	var sessionID uuid.UUID
	if err := testDB.Pool().QueryRow(context.Background(), `SELECT session_id FROM relay_codes WHERE code_hash = $1`, hashToken(response.Code)).Scan(&sessionID); err != nil {
		t.Fatalf("read relay session: %v", err)
	}
	if rows, err := q.RevokeUserSessionByID(context.Background(), dbq.RevokeUserSessionByIDParams{ID: toPgUUID(sessionID), UserID: toPgUUID(userID)}); err != nil || rows != 1 {
		t.Fatalf("revoke origin session = (%d, %v)", rows, err)
	}

	rec := httptest.NewRecorder()
	handleRelayCallback(rec, relayCallbackRequest(t, response.CallbackUrl, nonce), testDB, testJWTSecret, agentID, zap.NewNop())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("callback after session revoke status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if cookieByName(rec.Result().Cookies(), relayCookieName) != nil {
		t.Fatal("callback after session revoke issued a cookie")
	}
}

func TestRelayNoncePreventsLoginCSRF(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	agent, err := dbq.New(testDB.Pool()).GetAgentByID(context.Background(), toPgUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	attackerNonce, _ := newRelaySecret()
	victimNonce, _ := newRelaySecret()
	response := generateRelayCode(t, userID, "https://"+agent.Slug+".agents.test/", attackerNonce, "agents.test", "https://airlock.test")

	victimReq := relayCallbackRequest(t, response.CallbackUrl, victimNonce)
	victimRec := httptest.NewRecorder()
	handleRelayCallback(victimRec, victimReq, testDB, testJWTSecret, agentID, zap.NewNop())
	if victimRec.Code != http.StatusUnauthorized {
		t.Fatalf("victim callback status = %d, want %d", victimRec.Code, http.StatusUnauthorized)
	}
	if cookieByName(victimRec.Result().Cookies(), relayCookieName) != nil {
		t.Fatal("nonce-mismatched callback fixed the victim session")
	}
	assertRelayNonceCleared(t, victimRec)

	attackerReq := relayCallbackRequest(t, response.CallbackUrl, attackerNonce)
	attackerRec := httptest.NewRecorder()
	handleRelayCallback(attackerRec, attackerReq, testDB, testJWTSecret, agentID, zap.NewNop())
	if attackerRec.Code != http.StatusUnauthorized {
		t.Fatalf("code survived nonce mismatch: status = %d", attackerRec.Code)
	}
}

func TestRelayRequiresCanonicalSecureTarget(t *testing.T) {
	skipIfNoDB(t)
	agentID, userID := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	agent, err := q.GetAgentByID(context.Background(), toPgUUID(agentID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	nonce, _ := newRelaySecret()

	rec := generateRelayCodeResponse(t, userID, "http://"+agent.Slug+".agents.test/", nonce, "agents.test", "https://airlock.test")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HTTP production target status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	localRec := generateRelayCodeResponse(t, userID, "http://"+agent.Slug+".localhost/", nonce, "localhost", "https://localhost")
	if localRec.Code != http.StatusOK {
		t.Fatalf("localhost HTTP target status = %d, want %d; body: %s", localRec.Code, http.StatusOK, localRec.Body.String())
	}
}

func TestRelayRejectsForcedPasswordChange(t *testing.T) {
	nonce, _ := newRelaySecret()
	body, err := protojson.Marshal(&airlockv1.GenerateRelayCodeRequest{ReturnUrl: "https://demo.agents.test/private", Nonce: nonce})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	token, err := auth.IssueToken(testJWTSecret, uuid.New(), "user@example.com", "User", "user", true)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	h := &relayHandler{agentDomain: "agents.test", publicURL: "https://airlock.test", logger: zap.NewNop()}
	handler := auth.Middleware(testJWTSecret)(http.HandlerFunc(h.GenerateCode))
	req := httptest.NewRequest(http.MethodPost, "/auth/relay-code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestRelaySessionCookieIsAgentBound(t *testing.T) {
	userID := uuid.New()
	agentID := uuid.New()
	claims := &relayClaims{UserID: userID.String(), SessionID: uuid.NewString(), Email: "user@example.com", TenantRole: "user"}
	req := httptest.NewRequest(http.MethodGet, "https://demo.agents.test/__air/callback", nil)
	rec := httptest.NewRecorder()
	if err := issueSessionCookie(rec, req, testJWTSecret, agentID, claims); err != nil {
		t.Fatalf("issueSessionCookie: %v", err)
	}
	cookie := cookieByName(rec.Result().Cookies(), relayCookieName)
	if cookie == nil {
		t.Fatalf("missing %s cookie", relayCookieName)
	}
	if _, err := auth.ValidateSubdomainToken(testJWTSecret, cookie.Value, agentID); err != nil {
		t.Fatalf("ValidateSubdomainToken(target): %v", err)
	}
	if _, err := auth.ValidateSubdomainToken(testJWTSecret, cookie.Value, uuid.New()); err == nil {
		t.Fatal("session cookie accepted for another agent")
	}
}

func generateRelayCode(t *testing.T, userID uuid.UUID, returnURL, nonce, agentDomain, publicURL string) *airlockv1.GenerateRelayCodeResponse {
	t.Helper()
	rec := generateRelayCodeResponse(t, userID, returnURL, nonce, agentDomain, publicURL)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate relay code status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var response airlockv1.GenerateRelayCodeResponse
	decodeProtoResp(t, rec, &response)
	return &response
}

func generateRelayCodeResponse(t *testing.T, userID uuid.UUID, returnURL, nonce, agentDomain, publicURL string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := protojson.Marshal(&airlockv1.GenerateRelayCodeRequest{ReturnUrl: returnURL, Nonce: nonce})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	user, err := dbq.New(testDB.Pool()).GetUserByID(context.Background(), toPgUUID(userID))
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	token, _, err := issueUserSessionTokens(context.Background(), testDB, testJWTSecret, user, userSessionKindWeb, webClientName, "relay test")
	if err != nil {
		t.Fatalf("issueUserSessionTokens: %v", err)
	}
	h := &relayHandler{db: testDB, agentDomain: agentDomain, publicURL: publicURL, logger: zap.NewNop()}
	handler := auth.Middleware(testJWTSecret)(http.HandlerFunc(h.GenerateCode))
	req := httptest.NewRequest(http.MethodPost, "/auth/relay-code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func relayCallbackRequest(t *testing.T, callbackURL, nonce string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	req.AddCookie(&http.Cookie{Name: relayNonceCookieName(req), Value: nonce, Path: "/"})
	return req
}

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func assertRelayNonceCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	cookie := cookieByName(rec.Result().Cookies(), relayNonceName)
	if cookie == nil || cookie.MaxAge >= 0 {
		t.Fatalf("relay nonce cookie was not cleared: %v", rec.Header().Values("Set-Cookie"))
	}
}
