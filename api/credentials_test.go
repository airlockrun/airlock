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

	"github.com/airlockrun/airlock/agentapi"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/oauth"
	connsvc "github.com/airlockrun/airlock/service/connections"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// --- test helpers for user-authenticated routes ---

func testCredentialHandler() *credentialHandler {
	disc := func(ctx context.Context, serverURL string, authInjection []byte, creds string) ([]connsvc.ToolInfo, string, error) {
		tools, instructions, err := agentapi.DiscoverMCPTools(ctx, serverURL, authInjection, creds)
		if err != nil {
			return nil, "", err
		}
		out := make([]connsvc.ToolInfo, len(tools))
		for i, t := range tools {
			out[i] = connsvc.ToolInfo{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema}
		}
		return out, instructions, nil
	}
	noopRefresh := func(ctx context.Context, agentID uuid.UUID) error { return nil }
	return newCredentialHandler(connsvc.New(
		testDB, testEncryptor(), oauth.NewClient(),
		"http://localhost:8080", noopRefresh, zap.NewNop(),
		disc, agentapi.DiscoverMCPAuth, agentapi.InjectAuth, agentapi.MCPHTTPClient,
	))
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
	return requestJSONAs(t, method, path, userID, "user", body)
}

// requestJSONAs creates an HTTP request with a JWT for the given tenant
// role. Used by tests that need to exercise role-gated handlers.
func requestJSONAs(t *testing.T, method, path string, userID uuid.UUID, role string, body any) *http.Request {
	t.Helper()
	var reqBody string
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = string(b)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	token, err := auth.IssueToken(testJWTSecret, userID, "test@example.com", "", role, false)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// registerTestConnection records a connection need and a resource bound to it,
// mirroring the real model (sync records the need; a configure creates + binds
// the resource). Credential ops resolve the bound resource via the need.
func registerTestConnection(t *testing.T, agentID uuid.UUID, slug, authMode string) {
	t.Helper()
	q := dbq.New(testDB.Pool())
	conn, err := q.UpsertConnection(context.Background(), dbq.UpsertConnectionParams{
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
		AuthParams:    []byte("{}"),
		Headers:       []byte("{}"),
	})
	if err != nil {
		t.Fatalf("upsert connection: %v", err)
	}
	if err := q.UpsertResourceNeed(context.Background(), dbq.UpsertResourceNeedParams{
		AgentID: toPgUUID(agentID), Type: "connection", Slug: slug, Description: "Test " + slug,
		SetupInstructions: "", ExpectedUrl: "https://api.example.com", ExpectedScopes: "read write",
		Spec: []byte("{}"),
	}); err != nil {
		t.Fatalf("upsert connection need: %v", err)
	}
	if err := q.BindConnectionNeed(context.Background(), dbq.BindConnectionNeedParams{
		AgentID: toPgUUID(agentID), Slug: slug, ResourceID: conn.ID,
	}); err != nil {
		t.Fatalf("bind connection need: %v", err)
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
	decodeProtoResp(t, rec, &resp)
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
	decodeProtoResp(t, rec, &resp)
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
	decodeProtoResp(t, rec, &resp)
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
	decodeProtoResp(t, rec, &resp)
	if len(resp.Connections) < 2 {
		t.Errorf("expected at least 2 connections, got %d", len(resp.Connections))
	}
}

func TestSetOAuthAppThenStart(t *testing.T) {
	skipIfNoDB(t)
	ch := testCredentialHandler()
	agentID, userID := testAgentAndUser(t)
	registerTestConnection(t, agentID, "gcloud", "oauth")

	startRouter := userRouter(func(r chi.Router) {
		r.Post("/api/v1/credentials/oauth/start", ch.OAuthStart)
	})
	setRouter := userRouter(func(r chi.Router) {
		r.Put("/api/v1/agents/{agentID}/credentials/{slug}/oauth-app", ch.SetOAuthApp)
	})
	startBody := map[string]string{"agent_id": agentID.String(), "slug": "gcloud"}

	t.Run("start without app fails", func(t *testing.T) {
		req := userRequestJSON(t, "POST", "/api/v1/credentials/oauth/start", userID, startBody)
		rec := httptest.NewRecorder()
		startRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("set oauth app", func(t *testing.T) {
		body := map[string]string{"client_id": "test-client-id", "client_secret": "test-client-secret"}
		req := userRequestJSON(t, "PUT",
			fmt.Sprintf("/api/v1/agents/%s/credentials/gcloud/oauth-app", agentID), userID, body)
		rec := httptest.NewRecorder()
		setRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; body: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("start succeeds and returns PKCE authorize url", func(t *testing.T) {
		req := userRequestJSON(t, "POST", "/api/v1/credentials/oauth/start", userID, startBody)
		rec := httptest.NewRecorder()
		startRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; body: %s", rec.Code, rec.Body.String())
		}
		var resp airlockv1.OAuthStartResponse
		decodeProtoResp(t, rec, &resp)
		if resp.AuthorizeUrl == "" {
			t.Fatal("expected authorize_url in response")
		}
		u, err := url.Parse(resp.AuthorizeUrl)
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
	})
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
	conn, err := q.UpsertConnection(context.Background(), dbq.UpsertConnectionParams{
		AgentID:       toPgUUID(agentID),
		Slug:          "mock-oauth",
		Name:          "Mock OAuth",
		AuthMode:      "oauth",
		AuthUrl:       mockProvider.URL + "/authorize",
		TokenUrl:      mockProvider.URL + "/token",
		BaseUrl:       mockProvider.URL,
		AuthInjection: []byte(`{"type":"bearer"}`),
		Config:        []byte("{}"),
		AuthParams:    []byte("{}"),
		Headers:       []byte("{}"),
	})
	if err != nil {
		t.Fatalf("upsert connection: %v", err)
	}
	if err := q.UpsertResourceNeed(context.Background(), dbq.UpsertResourceNeedParams{
		AgentID: toPgUUID(agentID), Type: "connection", Slug: "mock-oauth", Description: "Mock OAuth",
		SetupInstructions: "", ExpectedUrl: mockProvider.URL, ExpectedScopes: "", Spec: []byte("{}"),
	}); err != nil {
		t.Fatalf("upsert connection need: %v", err)
	}
	if err := q.BindConnectionNeed(context.Background(), dbq.BindConnectionNeedParams{
		AgentID: toPgUUID(agentID), Slug: "mock-oauth", ResourceID: conn.ID,
	}); err != nil {
		t.Fatalf("bind connection need: %v", err)
	}

	// Set OAuth app credentials.
	enc := testEncryptor()
	encClientID, _ := enc.Put(context.Background(), "test/client_id", "mock-client-id")
	encClientSecret, _ := enc.Put(context.Background(), "test/client_secret", "mock-client-secret")
	if err := q.UpdateConnectionOAuthAppByID(context.Background(), dbq.UpdateConnectionOAuthAppByIDParams{
		ID:           conn.ID,
		ClientID:     encClientID,
		ClientSecret: encClientSecret,
	}); err != nil {
		t.Fatalf("update oauth app: %v", err)
	}

	startRouter := userRouter(func(r chi.Router) {
		r.Post("/api/v1/credentials/oauth/start", ch.OAuthStart)
	})
	callbackRouter := chi.NewRouter()
	callbackRouter.Get("/api/v1/credentials/oauth/callback", ch.OAuthCallback)
	statusRouter := userRouter(func(r chi.Router) {
		r.Get("/api/v1/agents/{agentID}/credentials/{slug}", ch.CredentialStatus)
	})

	var state string
	t.Run("start returns state", func(t *testing.T) {
		startBody := map[string]string{"agent_id": agentID.String(), "slug": "mock-oauth"}
		req := userRequestJSON(t, "POST", "/api/v1/credentials/oauth/start", userID, startBody)
		rec := httptest.NewRecorder()
		startRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d; body: %s", rec.Code, rec.Body.String())
		}
		var resp airlockv1.OAuthStartResponse
		decodeProtoResp(t, rec, &resp)
		u, err := url.Parse(resp.AuthorizeUrl)
		if err != nil {
			t.Fatalf("parse authorize_url: %v", err)
		}
		state = u.Query().Get("state")
		if state == "" {
			t.Fatal("no state in authorize URL")
		}
	})

	t.Run("callback redirects", func(t *testing.T) {
		if state == "" {
			t.Skip("start subtest did not produce a state token")
		}
		callbackURL := fmt.Sprintf("/api/v1/credentials/oauth/callback?code=mock-auth-code&state=%s", state)
		req := httptest.NewRequest("GET", callbackURL, nil)
		rec := httptest.NewRecorder()
		callbackRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302; body: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("status reports authorized", func(t *testing.T) {
		req := userRequestJSON(t, "GET",
			fmt.Sprintf("/api/v1/agents/%s/credentials/mock-oauth", agentID), userID, nil)
		rec := httptest.NewRecorder()
		statusRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var resp airlockv1.CredentialStatusResponse
		decodeProtoResp(t, rec, &resp)
		if !resp.Authorized {
			t.Error("expected authorized = true after OAuth callback")
		}
	})
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
