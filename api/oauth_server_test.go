package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/auth/lockout"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const oauthTestPublicURL = "https://airlock.example.com"

func TestOAuthRefreshRotationSingleWinner(t *testing.T) {
	skipIfNoDB(t)
	h := newOAuthServerHandler(testDB, testJWTSecret, oauthTestPublicURL, zap.NewNop())
	agentID, userID := testAgentAndUser(t)
	clientID := createOAuthTestClient(t, []string{"authorization_code", "refresh_token"})
	q := dbq.New(testDB.Pool())
	if err := q.UpsertGrant(context.Background(), dbq.UpsertGrantParams{
		UserID: toPgUUID(userID), ClientID: clientID, AgentID: toPgUUID(agentID), Scope: "mcp",
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	raw := "refresh-token-for-concurrency-test"
	familyID := uuid.New()
	if err := q.CreateRefreshToken(context.Background(), dbq.CreateRefreshTokenParams{
		TokenHash: hashToken(raw), UserID: toPgUUID(userID), ClientID: clientID,
		AgentID: toPgUUID(agentID), Scope: "mcp", FamilyID: toPgUUID(familyID),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	recorders := make([]*httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := range recorders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			form := url.Values{"refresh_token": {raw}, "client_id": {clientID}}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorders[i] = httptest.NewRecorder()
			h.tokenRefresh(recorders[i], req)
		}(i)
	}
	close(start)
	wg.Wait()

	statuses := map[int]int{}
	for _, rec := range recorders {
		statuses[rec.Code]++
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusBadRequest] != 1 {
		t.Fatalf("refresh statuses = %v; bodies = %q / %q", statuses, recorders[0].Body.String(), recorders[1].Body.String())
	}
	row, err := q.GetRefreshTokenByHash(context.Background(), hashToken(raw))
	if err != nil || !row.ConsumedAt.Valid {
		t.Fatalf("original refresh not consumed: row=%#v err=%v", row, err)
	}
}

func TestOAuthAuthorizeRejectsUserWithoutAgentEntitlement(t *testing.T) {
	skipIfNoDB(t)
	h := newOAuthServerHandler(testDB, testJWTSecret, oauthTestPublicURL, zap.NewNop())
	agentID, _ := testAgentAndUser(t)
	outsider := seedDeviceLoginUser(t)
	clientID := createOAuthTestClient(t, []string{"authorization_code"})
	verifier := strings.Repeat("a", 43)
	challenge := pkceChallenge(verifier)
	redirectURI := "https://client.example.com/callback"
	query := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"mcp"},
		"resource": {oauthTestPublicURL + "/api/agent/" + agentID.String() + "/mcp"}, "state": {"bound-state"},
	}
	user, err := dbq.New(testDB.Pool()).GetUserByID(context.Background(), toPgUUID(outsider))
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := issueUserSessionTokens(context.Background(), testDB, testJWTSecret, user, userSessionKindWeb, webClientName, "test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "airlock_session", Value: token})
	rec := httptest.NewRecorder()
	h.Authorize(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "access_denied" || location.Query().Get("state") != "bound-state" {
		t.Fatalf("location=%q err=%v", rec.Header().Get("Location"), err)
	}
}

func TestOAuthAuthorizePersistsConsentTransaction(t *testing.T) {
	skipIfNoDB(t)
	h := newOAuthServerHandler(testDB, testJWTSecret, oauthTestPublicURL, zap.NewNop())
	agentID, userID := testAgentAndUser(t)
	clientID := createOAuthTestClient(t, []string{"authorization_code"})
	challenge := pkceChallenge(strings.Repeat("a", 43))
	query := url.Values{
		"client_id": {clientID}, "redirect_uri": {"https://client.example.com/callback"}, "response_type": {"code"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"mcp"},
		"resource": {oauthTestPublicURL + "/api/agent/" + agentID.String() + "/mcp"}, "state": {"bound-state"},
	}
	user, err := dbq.New(testDB.Pool()).GetUserByID(context.Background(), toPgUUID(userID))
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := issueUserSessionTokens(context.Background(), testDB, testJWTSecret, user, userSessionKindWeb, webClientName, "test")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: accessCookieName, Value: token})
	rec := httptest.NewRecorder()
	h.Authorize(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	consentToken := location.Query().Get("consent_token")
	binding, err := h.verifyConsentBinding(consentToken)
	if err != nil {
		t.Fatal(err)
	}
	var bindingHash []byte
	var storedUserID, storedClientID, storedAgentID string
	if err := testDB.Pool().QueryRow(context.Background(), `
		SELECT binding_hash, user_id::text, client_id, agent_id::text
		FROM oauth_consent_transactions
		WHERE transaction_id = $1
	`, binding.TransactionID).Scan(&bindingHash, &storedUserID, &storedClientID, &storedAgentID); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bindingHash, hashToken(consentToken)) || storedUserID != userID.String() || storedClientID != clientID || storedAgentID != agentID.String() {
		t.Fatalf("stored consent binding mismatch: hash=%x user=%s client=%s agent=%s", bindingHash, storedUserID, storedClientID, storedAgentID)
	}
}

func TestOAuthDCRRateLimitRejectsSpoofedForwardingHeaders(t *testing.T) {
	skipIfNoDB(t)
	h := newOAuthServerHandler(testDB, testJWTSecret, oauthTestPublicURL, zap.NewNop())
	handler := RealIP(ParseRealIPConfig("172.16.0.0/12", 1, realIPTestSecret))(http.HandlerFunc(h.Register))
	body := []byte(`{"client_name":"test","redirect_uris":["https://client.example.com/callback"]}`)
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(body))
		req.RemoteAddr = "172.18.0.9:4321"
		req.Header.Set("X-Forwarded-For", "198.51.100."+strconv.Itoa(i+1))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		want := http.StatusCreated
		if i == 10 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("request %d status=%d want=%d body=%s", i+1, rec.Code, want, rec.Body.String())
		}
	}
}

func TestOAuthDCRRateLimitSeparatesAuthenticatedForwardedClients(t *testing.T) {
	skipIfNoDB(t)
	h := newOAuthServerHandler(testDB, testJWTSecret, oauthTestPublicURL, zap.NewNop())
	handler := RealIP(ParseRealIPConfig("172.16.0.0/12", 1, realIPTestSecret))(http.HandlerFunc(h.Register))
	body := []byte(`{"client_name":"test","redirect_uris":["https://client.example.com/callback"]}`)

	register := func(ip string) int {
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", bytes.NewReader(body))
		req.RemoteAddr = "172.18.0.10:4321"
		req.Header.Set(proxyAuthHeader, realIPTestSecret)
		req.Header.Set("X-Forwarded-For", ip)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 10; i++ {
		for _, ip := range []string{"198.51.100.201", "198.51.100.202"} {
			if got := register(ip); got != http.StatusCreated {
				t.Fatalf("client %s request %d status=%d, want %d", ip, i+1, got, http.StatusCreated)
			}
		}
	}
	if got := register("198.51.100.201"); got != http.StatusTooManyRequests {
		t.Fatalf("limited client status=%d, want %d", got, http.StatusTooManyRequests)
	}
	if got := register("198.51.100.202"); got != http.StatusTooManyRequests {
		t.Fatalf("second limited client status=%d, want %d", got, http.StatusTooManyRequests)
	}
}

func TestOAuthConsentBindingRejectsTampering(t *testing.T) {
	h := &oauthServerHandler{jwtSecret: testJWTSecret}
	binding := consentBinding{TransactionID: uuid.NewString(), UserID: uuid.NewString(), ClientID: "client", RedirectURI: "https://client.example/cb", State: "state", CodeChallenge: pkceChallenge(strings.Repeat("a", 43)), Scope: "mcp", Resource: "resource", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	token, err := h.signConsentBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := h.verifyConsentBinding(token); err != nil || got != binding {
		t.Fatalf("verify = %#v, %v", got, err)
	}
	replacement := byte('A')
	if token[0] == replacement {
		replacement = 'B'
	}
	tampered := string(replacement) + token[1:]
	if _, err := h.verifyConsentBinding(tampered); err == nil {
		t.Fatal("tampered consent token accepted")
	}
}

func TestOAuthConsentDecisionHasSingleWinner(t *testing.T) {
	skipIfNoDB(t)
	h := newOAuthServerHandler(testDB, testJWTSecret, oauthTestPublicURL, zap.NewNop())
	agentID, userID := testAgentAndUser(t)
	clientID := createOAuthTestClient(t, []string{"authorization_code"})
	req := createOAuthConsentTestRequest(t, h, userID, clientID, agentID)

	start := make(chan struct{})
	recorders := make([]*httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := range recorders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			recorders[i] = performOAuthConsent(t, h, userID, req)
		}(i)
	}
	close(start)
	wg.Wait()

	statuses := map[int]int{}
	for _, rec := range recorders {
		statuses[rec.Code]++
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusBadRequest] != 1 {
		t.Fatalf("consent statuses = %v; bodies = %q / %q", statuses, recorders[0].Body.String(), recorders[1].Body.String())
	}
	var codes, transactions int
	if err := testDB.Pool().QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM oauth_authz_codes WHERE client_id = $1),
		       (SELECT count(*) FROM oauth_consent_transactions WHERE client_id = $1)
	`, clientID).Scan(&codes, &transactions); err != nil {
		t.Fatal(err)
	}
	if codes != 1 || transactions != 0 {
		t.Fatalf("codes=%d transactions=%d; want 1, 0", codes, transactions)
	}
}

func TestOAuthConsentDenyIsSingleUse(t *testing.T) {
	skipIfNoDB(t)
	h := newOAuthServerHandler(testDB, testJWTSecret, oauthTestPublicURL, zap.NewNop())
	agentID, userID := testAgentAndUser(t)
	clientID := createOAuthTestClient(t, []string{"authorization_code"})
	req := createOAuthConsentTestRequest(t, h, userID, clientID, agentID)
	req.Decision = "deny"

	if rec := performOAuthConsent(t, h, userID, req); rec.Code != http.StatusOK {
		t.Fatalf("deny status=%d body=%s", rec.Code, rec.Body.String())
	}
	req.Decision = "approve"
	if rec := performOAuthConsent(t, h, userID, req); rec.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := dbq.New(testDB.Pool()).GetActiveGrant(context.Background(), dbq.GetActiveGrantParams{
		UserID: toPgUUID(userID), ClientID: clientID, AgentID: toPgUUID(agentID),
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("grant after deny replay: %v", err)
	}
}

func TestOAuthGrantRevocationInvalidatesConsentReplay(t *testing.T) {
	skipIfNoDB(t)
	h := newOAuthServerHandler(testDB, testJWTSecret, oauthTestPublicURL, zap.NewNop())
	agentID, userID := testAgentAndUser(t)
	clientID := createOAuthTestClient(t, []string{"authorization_code"})
	consumed := createOAuthConsentTestRequest(t, h, userID, clientID, agentID)
	if rec := performOAuthConsent(t, h, userID, consumed); rec.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
	}
	pending := createOAuthConsentTestRequest(t, h, userID, clientID, agentID)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/oauth/grants/"+clientID+"/"+agentID.String(), nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("clientID", clientID)
	routeCtx.URLParams.Add("agentID", agentID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	rec := performOAuthAuthenticatedRequest(t, userID, req, http.HandlerFunc(h.RevokeGrant))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d body=%s", rec.Code, rec.Body.String())
	}

	for name, replay := range map[string]consentRequest{"consumed": consumed, "pending": pending} {
		if rec := performOAuthConsent(t, h, userID, replay); rec.Code != http.StatusBadRequest {
			t.Errorf("%s replay status=%d body=%s", name, rec.Code, rec.Body.String())
		}
	}
	if _, err := dbq.New(testDB.Pool()).GetActiveGrant(context.Background(), dbq.GetActiveGrantParams{
		UserID: toPgUUID(userID), ClientID: clientID, AgentID: toPgUUID(agentID),
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("grant reopened after revocation: %v", err)
	}
}

func TestInboundOAuthGCConsentTransactionsAndClients(t *testing.T) {
	skipIfNoDB(t)
	h := newOAuthServerHandler(testDB, testJWTSecret, oauthTestPublicURL, zap.NewNop())
	agentID, userID := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())

	oldUnused := createOAuthTestClient(t, []string{"authorization_code"})
	oldInactive := createOAuthTestClient(t, []string{"authorization_code"})
	freshUnused := createOAuthTestClient(t, []string{"authorization_code"})
	withGrant := createOAuthTestClient(t, []string{"authorization_code"})
	withCode := createOAuthTestClient(t, []string{"authorization_code"})
	withRefresh := createOAuthTestClient(t, []string{"authorization_code", "refresh_token"})
	withConsent := createOAuthTestClient(t, []string{"authorization_code"})

	for _, clientID := range []string{oldInactive, withGrant, withCode, withRefresh, withConsent} {
		if _, err := testDB.Pool().Exec(context.Background(), `UPDATE oauth_clients SET created_at = now() - interval '200 days', last_used_at = now() - interval '181 days' WHERE client_id = $1`, clientID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testDB.Pool().Exec(context.Background(), `UPDATE oauth_clients SET created_at = now() - interval '25 hours' WHERE client_id = $1`, oldUnused); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertGrant(context.Background(), dbq.UpsertGrantParams{
		UserID: toPgUUID(userID), ClientID: withGrant, AgentID: toPgUUID(agentID), Scope: "mcp",
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateAuthzCode(context.Background(), dbq.CreateAuthzCodeParams{
		Code: uuid.NewString(), UserID: toPgUUID(userID), ClientID: withCode, AgentID: toPgUUID(agentID),
		RedirectUri: "https://client.example.com/callback", CodeChallenge: pkceChallenge(strings.Repeat("a", 43)),
		Scope: "mcp", Resource: oauthTestPublicURL + "/api/agent/" + agentID.String() + "/mcp",
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateRefreshToken(context.Background(), dbq.CreateRefreshTokenParams{
		TokenHash: hashToken(uuid.NewString()), UserID: toPgUUID(userID), ClientID: withRefresh,
		AgentID: toPgUUID(agentID), Scope: "mcp", FamilyID: toPgUUID(uuid.New()),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	_ = createOAuthConsentTestRequest(t, h, userID, withConsent, agentID)

	expired := createOAuthConsentTestRequest(t, h, userID, oldUnused, agentID)
	transactionID, err := consentTransactionID(h, expired.ConsentToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Pool().Exec(context.Background(), `UPDATE oauth_consent_transactions SET expires_at = now() - interval '1 second' WHERE transaction_id = $1`, transactionID); err != nil {
		t.Fatal(err)
	}

	NewInboundOAuthGC(testDB, zap.NewNop()).sweep(context.Background())

	for _, clientID := range []string{oldUnused, oldInactive} {
		if _, err := q.GetOAuthClient(context.Background(), clientID); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("client %s was not pruned: %v", clientID, err)
		}
	}
	for _, clientID := range []string{freshUnused, withGrant, withCode, withRefresh, withConsent} {
		if _, err := q.GetOAuthClient(context.Background(), clientID); err != nil {
			t.Errorf("client %s was pruned: %v", clientID, err)
		}
	}
	var expiredTransactions int
	if err := testDB.Pool().QueryRow(context.Background(), `SELECT count(*) FROM oauth_consent_transactions WHERE transaction_id = $1`, transactionID).Scan(&expiredTransactions); err != nil {
		t.Fatal(err)
	}
	if expiredTransactions != 0 {
		t.Fatalf("expired consent transactions=%d; want 0", expiredTransactions)
	}
}

func TestOAuthClientCleanupConcurrentBoundedSweeps(t *testing.T) {
	skipIfNoDB(t)
	const clients = 150
	for range clients {
		clientID := createOAuthTestClient(t, []string{"authorization_code"})
		if _, err := testDB.Pool().Exec(context.Background(), `UPDATE oauth_clients SET created_at = now() - interval '25 hours' WHERE client_id = $1`, clientID); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	deleted := make(chan int64, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			n, err := dbq.New(testDB.Pool()).CleanupInactiveOAuthClients(context.Background())
			deleted <- n
			errs <- err
		}()
	}
	close(start)
	var total int64
	for range 2 {
		total += <-deleted
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if total != clients {
		t.Fatalf("deleted=%d; want %d", total, clients)
	}
	var remaining int
	if err := testDB.Pool().QueryRow(context.Background(), `SELECT count(*) FROM oauth_clients`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("remaining clients=%d; want 0", remaining)
	}
}

func TestOAuthStrictRedirectAndPKCEGrammar(t *testing.T) {
	redirects := map[string]bool{
		"https://client.example/cb":          true,
		"http://127.0.0.1:9876/cb":           true,
		"http://[::1]:9876/cb":               true,
		"http://localhost/cb":                false,
		"https://user@client.example/cb":     false,
		"https://client.example/cb#fragment": false,
		"javascript://client.example/cb":     false,
	}
	for raw, want := range redirects {
		if got := isValidRedirectURI(raw); got != want {
			t.Errorf("isValidRedirectURI(%q)=%v want %v", raw, got, want)
		}
	}
	verifier := strings.Repeat("a", 43)
	challenge := pkceChallenge(verifier)
	if !validPKCEVerifier(verifier) || !validPKCEChallenge(challenge) || !verifyPKCE(verifier, challenge) {
		t.Fatal("valid PKCE pair rejected")
	}
	if validPKCEVerifier(strings.Repeat("a", 42)) || validPKCEVerifier(strings.Repeat("a", 42)+"=") || validPKCEChallenge(challenge+"=") {
		t.Fatal("invalid PKCE grammar accepted")
	}
}

func TestOAuthClientMetadataEnforced(t *testing.T) {
	client := dbq.OauthClient{
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		TokenEndpointAuthMethod: "none", Scope: "mcp",
	}
	if !oauthClientAllows(client, "authorization_code", "code", "mcp") {
		t.Fatal("registered authorization code metadata rejected")
	}
	if oauthClientAllows(client, "refresh_token", "", "mcp") || oauthClientAllows(client, "authorization_code", "code", "openid") {
		t.Fatal("unregistered grant or scope accepted")
	}
}

func TestOAuthTokenResponseIsNoStore(t *testing.T) {
	h := &oauthServerHandler{pad: lockout.Policy{}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=unsupported"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Token(rec, req)
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %v", rec.Header())
	}
}

func createOAuthTestClient(t *testing.T, grantTypes []string) string {
	t.Helper()
	clientID := "test-client-" + uuid.NewString()
	_, err := dbq.New(testDB.Pool()).CreateOAuthClient(context.Background(), dbq.CreateOAuthClientParams{
		ClientID: clientID, ClientName: "Test Client", RedirectUris: []string{"https://client.example.com/callback"},
		GrantTypes: grantTypes, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none", Scope: "mcp",
	})
	if err != nil {
		t.Fatalf("CreateOAuthClient: %v", err)
	}
	return clientID
}

func createOAuthConsentTestRequest(t *testing.T, h *oauthServerHandler, userID uuid.UUID, clientID string, agentID uuid.UUID) consentRequest {
	t.Helper()
	expiresAt := time.Now().Add(10 * time.Minute)
	resource := oauthTestPublicURL + "/api/agent/" + agentID.String() + "/mcp"
	binding := consentBinding{
		TransactionID: uuid.NewString(), UserID: userID.String(), ClientID: clientID,
		RedirectURI: "https://client.example.com/callback", State: "state",
		CodeChallenge: pkceChallenge(strings.Repeat("a", 43)), Scope: "mcp",
		Resource: resource, ExpiresAt: expiresAt.Unix(),
	}
	token, err := h.signConsentBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	transactionID, err := uuid.Parse(binding.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := dbq.New(testDB.Pool()).CreateOAuthConsentTransaction(context.Background(), dbq.CreateOAuthConsentTransactionParams{
		TransactionID: toPgUUID(transactionID), BindingHash: hashToken(token), UserID: toPgUUID(userID),
		ClientID: clientID, AgentID: toPgUUID(agentID), ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	return consentRequest{
		Decision: "approve", ClientID: clientID, RedirectURI: binding.RedirectURI, State: binding.State,
		CodeChallenge: binding.CodeChallenge, CodeChallengeMethod: "S256", Scope: "mcp",
		Resource: resource, ConsentToken: token,
	}
}

func performOAuthConsent(t *testing.T, h *oauthServerHandler, userID uuid.UUID, body consentRequest) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/consent", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", oauthTestPublicURL)
	return performOAuthAuthenticatedRequest(t, userID, req, http.HandlerFunc(h.Consent))
}

func performOAuthAuthenticatedRequest(t *testing.T, userID uuid.UUID, req *http.Request, handler http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	token, err := auth.IssueToken(testJWTSecret, userID, "oauth-user@example.com", "OAuth User", "user", false)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	auth.Middleware(testJWTSecret)(handler).ServeHTTP(rec, req)
	return rec
}

func consentTransactionID(h *oauthServerHandler, token string) (uuid.UUID, error) {
	binding, err := h.verifyConsentBinding(token)
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(binding.TransactionID)
}

func pkceChallenge(verifier string) string {
	sum := hashToken(verifier)
	return base64.RawURLEncoding.EncodeToString(sum)
}
