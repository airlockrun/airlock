package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

// --- test helpers for user-authenticated routes ---

func testCredentialHandler() *credentialHandler {
	return &credentialHandler{
		db:          testDB,
		encryptor:   testEncryptor(),
		oauthClient: oauth.NewClient(),
		publicURL:   "http://localhost:8080",
		logger:      zap.NewNop(),
	}
}

// userRouter creates a chi router with JWT user auth middleware.
func userRouter(setup func(r chi.Router)) http.Handler {
	r := chi.NewRouter()
	r.Use(auth.Middleware(testJWTSecret))
	setup(r)
	return r
}

// userRequestJSON creates an HTTP request with a user JWT and JSON body.
func userRequestJSON(t *testing.T, method, path string, userID uuid.UUID, body any) *http.Request {
	t.Helper()
	var reqBody string
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = string(b)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	token, err := auth.IssueToken(testJWTSecret, userID, "test@example.com", "user")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// registerTestConnection inserts a connection for the agent.
func registerTestConnection(t *testing.T, agentID uuid.UUID, slug, authMode string) {
	t.Helper()
	q := dbq.New(testDB.Pool())
	_, err := q.UpsertConnection(context.Background(), dbq.UpsertConnectionParams{
		AgentID:       toPgUUID(agentID),
		Slug:          slug,
		Name:          "Test " + slug,
		AuthMode:      authMode,
		AuthUrl:       "https://provider.example.com/authorize",
		TokenUrl:      "https://provider.example.com/token",
		BaseUrl:       "https://api.example.com",
		Scopes:        "read write",
		AuthInjection: []byte(`{"type":"bearer"}`),
		Config:        []byte("{}"),
	})
	if err != nil {
		t.Fatalf("upsert connection: %v", err)
	}
}

func TestSetAPIKey(t *testing.T) {
	skipIfNoDB(t)
	ch := testCredentialHandler()
	agentID, userID := testAgentAndUser(t)
	registerTestConnection(t, agentID, "github", "token")

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/agents/{agentID}/credentials/{slug}", ch.SetAPIKey)
	})

	// Set API key.
	body := map[string]string{"api_key": "ghp_test123"}
	req := userRequestJSON(t, "POST",
		fmt.Sprintf("/api/v1/agents/%s/credentials/github", agentID), userID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("SetAPIKey: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.CredentialStatusResponse
	protojson.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Authorized {
		t.Error("expected authorized = true after setting API key")
	}

	// Verify credential status.
	statusRouter := userRouter(func(r chi.Router) {
		r.Get("/api/v1/agents/{agentID}/credentials/{slug}", ch.CredentialStatus)
	})
	req = userRequestJSON(t, "GET",
		fmt.Sprintf("/api/v1/agents/%s/credentials/github", agentID), userID, nil)
	rec = httptest.NewRecorder()
	statusRouter.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("CredentialStatus: status = %d", rec.Code)
	}
	protojson.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Authorized {
		t.Error("expected authorized = true from status check")
	}
}

func TestSetAPIKeyRejectsOAuth(t *testing.T) {
	skipIfNoDB(t)
	ch := testCredentialHandler()
	agentID, userID := testAgentAndUser(t)
	registerTestConnection(t, agentID, "google", "oauth")

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/agents/{agentID}/credentials/{slug}", ch.SetAPIKey)
	})

	body := map[string]string{"api_key": "should-fail"}
	req := userRequestJSON(t, "POST",
		fmt.Sprintf("/api/v1/agents/%s/credentials/google", agentID), userID, body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for OAuth connection, got %d", rec.Code)
	}
}

func TestRevokeCredential(t *testing.T) {
	skipIfNoDB(t)
	ch := testCredentialHandler()
	agentID, userID := testAgentAndUser(t)
	registerTestConnection(t, agentID, "slack", "token")

	// Set credential.
	setRouter := userRouter(func(r chi.Router) {
		r.Post("/api/v1/agents/{agentID}/credentials/{slug}", ch.SetAPIKey)
	})
	body := map[string]string{"api_key": "xoxb-test"}
	req := userRequestJSON(t, "POST",
		fmt.Sprintf("/api/v1/agents/%s/credentials/slack", agentID), userID, body)
	rec := httptest.NewRecorder()
	setRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("SetAPIKey: status = %d", rec.Code)
	}

	// Revoke.
	revokeRouter := userRouter(func(r chi.Router) {
		r.Delete("/api/v1/agents/{agentID}/credentials/{slug}", ch.RevokeCredential)
	})
	req = userRequestJSON(t, "DELETE",
		fmt.Sprintf("/api/v1/agents/%s/credentials/slack", agentID), userID, nil)
	rec = httptest.NewRecorder()
	revokeRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("Revoke: status = %d, want 204", rec.Code)
	}

	// Verify unauthorized.
	statusRouter := userRouter(func(r chi.Router) {
		r.Get("/api/v1/agents/{agentID}/credentials/{slug}", ch.CredentialStatus)
	})
	req = userRequestJSON(t, "GET",
		fmt.Sprintf("/api/v1/agents/%s/credentials/slack", agentID), userID, nil)
	rec = httptest.NewRecorder()
	statusRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Status: status = %d", rec.Code)
	}
	var resp airlockv1.CredentialStatusResponse
	protojson.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Authorized {
		t.Error("expected authorized = false after revoke")
	}
}

func TestListConnections(t *testing.T) {
	skipIfNoDB(t)
	ch := testCredentialHandler()
	agentID, userID := testAgentAndUser(t)
	registerTestConnection(t, agentID, "svc-a", "token")
	registerTestConnection(t, agentID, "svc-b", "oauth")

	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/agents/{agentID}/connections", ch.ListConnections)
	})

	req := userRequestJSON(t, "GET",
		fmt.Sprintf("/api/v1/agents/%s/connections", agentID), userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("ListConnections: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp airlockv1.ListConnectionsResponse
	protojson.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Connections) < 2 {
		t.Errorf("expected at least 2 connections, got %d", len(resp.Connections))
	}
}

func TestSetOAuthAppThenStart(t *testing.T) {
	skipIfNoDB(t)
	ch := testCredentialHandler()
	agentID, userID := testAgentAndUser(t)
	registerTestConnection(t, agentID, "gcloud", "oauth")

	// Start without OAuth app → should fail.
	startRouter := userRouter(func(r chi.Router) {
		r.Post("/api/v1/credentials/oauth/start", ch.OAuthStart)
	})
	startBody := map[string]string{"agent_id": agentID.String(), "slug": "gcloud"}
	req := userRequestJSON(t, "POST", "/api/v1/credentials/oauth/start", userID, startBody)
	rec := httptest.NewRecorder()
	startRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("OAuthStart without app: status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}

	// Set OAuth app.
	setRouter := userRouter(func(r chi.Router) {
		r.Put("/api/v1/agents/{agentID}/credentials/{slug}/oauth-app", ch.SetOAuthApp)
	})
	oauthAppBody := map[string]string{"client_id": "test-client-id", "client_secret": "test-client-secret"}
	req = userRequestJSON(t, "PUT",
		fmt.Sprintf("/api/v1/agents/%s/credentials/gcloud/oauth-app", agentID), userID, oauthAppBody)
	rec = httptest.NewRecorder()
	setRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("SetOAuthApp: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	// Now start should succeed → returns authorize_url.
	req = userRequestJSON(t, "POST", "/api/v1/credentials/oauth/start", userID, startBody)
	rec = httptest.NewRecorder()
	startRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("OAuthStart: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var startResp airlockv1.OAuthStartResponse
	protojson.Unmarshal(rec.Body.Bytes(), &startResp)
	if startResp.AuthorizeUrl == "" {
		t.Fatal("expected authorize_url in response")
	}

	// Verify the authorize URL points to the provider and includes PKCE params.
	u, err := url.Parse(startResp.AuthorizeUrl)
	if err != nil {
		t.Fatalf("parse authorize_url: %v", err)
	}
	if u.Host != "provider.example.com" {
		t.Errorf("authorize host = %q, want provider.example.com", u.Host)
	}
	if u.Query().Get("code_challenge") == "" {
		t.Error("missing code_challenge in authorize URL")
	}
	if u.Query().Get("state") == "" {
		t.Error("missing state in authorize URL")
	}
}

func TestOAuthCallbackFlow(t *testing.T) {
	skipIfNoDB(t)
	ch := testCredentialHandler()
	agentID, userID := testAgentAndUser(t)

	// Set up a mock OAuth provider token endpoint.
	mockProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "mock-access-token",
			"refresh_token": "mock-refresh-token",
			"token_type":    "bearer",
			"expires_in":    3600,
		})
	}))
	defer mockProvider.Close()

	// Register connection pointing to mock provider.
	q := dbq.New(testDB.Pool())
	_, err := q.UpsertConnection(context.Background(), dbq.UpsertConnectionParams{
		AgentID:       toPgUUID(agentID),
		Slug:          "mock-oauth",
		Name:          "Mock OAuth",
		AuthMode:      "oauth",
		AuthUrl:       mockProvider.URL + "/authorize",
		TokenUrl:      mockProvider.URL + "/token",
		BaseUrl:       mockProvider.URL,
		AuthInjection: []byte(`{"type":"bearer"}`),
		Config:        []byte("{}"),
	})
	if err != nil {
		t.Fatalf("upsert connection: %v", err)
	}

	// Set OAuth app credentials.
	enc := testEncryptor()
	encClientID, _ := enc.Encrypt("mock-client-id")
	encClientSecret, _ := enc.Encrypt("mock-client-secret")
	if err := q.UpdateConnectionOAuthApp(context.Background(), dbq.UpdateConnectionOAuthAppParams{
		AgentID:      toPgUUID(agentID),
		Slug:         "mock-oauth",
		ClientID:     encClientID,
		ClientSecret: encClientSecret,
	}); err != nil {
		t.Fatalf("update oauth app: %v", err)
	}

	// Start OAuth flow to get a state token.
	startRouter := userRouter(func(r chi.Router) {
		r.Post("/api/v1/credentials/oauth/start", ch.OAuthStart)
	})
	startBody := map[string]string{"agent_id": agentID.String(), "slug": "mock-oauth"}
	req := userRequestJSON(t, "POST", "/api/v1/credentials/oauth/start", userID, startBody)
	rec := httptest.NewRecorder()
	startRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("OAuthStart: status = %d; body: %s", rec.Code, rec.Body.String())
	}

	var startResp airlockv1.OAuthStartResponse
	protojson.Unmarshal(rec.Body.Bytes(), &startResp)

	// Extract state from authorize URL.
	u, _ := url.Parse(startResp.AuthorizeUrl)
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("no state in authorize URL")
	}

	// Simulate callback (no JWT needed — outside auth middleware).
	callbackRouter := chi.NewRouter()
	callbackRouter.Get("/api/v1/credentials/oauth/callback", ch.OAuthCallback)

	callbackURL := fmt.Sprintf("/api/v1/credentials/oauth/callback?code=mock-auth-code&state=%s", state)
	req = httptest.NewRequest("GET", callbackURL, nil)
	rec = httptest.NewRecorder()
	callbackRouter.ServeHTTP(rec, req)

	// Should redirect (302).
	if rec.Code != http.StatusFound {
		t.Fatalf("OAuthCallback: status = %d, want 302; body: %s", rec.Code, rec.Body.String())
	}

	// Verify credentials were stored.
	statusRouter := userRouter(func(r chi.Router) {
		r.Get("/api/v1/agents/{agentID}/credentials/{slug}", ch.CredentialStatus)
	})
	req = userRequestJSON(t, "GET",
		fmt.Sprintf("/api/v1/agents/%s/credentials/mock-oauth", agentID), userID, nil)
	rec = httptest.NewRecorder()
	statusRouter.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("CredentialStatus: status = %d", rec.Code)
	}
	var statusResp airlockv1.CredentialStatusResponse
	protojson.Unmarshal(rec.Body.Bytes(), &statusResp)
	if !statusResp.Authorized {
		t.Error("expected authorized = true after OAuth callback")
	}
}

func TestTestCredentialNoCredentials(t *testing.T) {
	skipIfNoDB(t)
	ch := testCredentialHandler()
	agentID, userID := testAgentAndUser(t)
	registerTestConnection(t, agentID, "nocreds", "token")

	router := userRouter(func(r chi.Router) {
		r.Post("/api/v1/agents/{agentID}/credentials/{slug}/test", ch.TestCredential)
	})

	req := userRequestJSON(t, "POST",
		fmt.Sprintf("/api/v1/agents/%s/credentials/nocreds/test", agentID), userID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("TestCredential with no creds: status = %d, want 400", rec.Code)
	}
}

func TestAccessDeniedForNonOwner(t *testing.T) {
	skipIfNoDB(t)
	ch := testCredentialHandler()
	agentID, _ := testAgentAndUser(t)
	registerTestConnection(t, agentID, "private", "token")

	// Create a different user.
	_, otherUserID := testAgentAndUser(t)

	router := userRouter(func(r chi.Router) {
		r.Get("/api/v1/agents/{agentID}/credentials/{slug}", ch.CredentialStatus)
	})

	req := userRequestJSON(t, "GET",
		fmt.Sprintf("/api/v1/agents/%s/credentials/private", agentID), otherUserID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("non-owner access: status = %d, want 403", rec.Code)
	}
}
