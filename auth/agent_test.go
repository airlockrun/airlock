package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestIssueAndValidateAgentToken(t *testing.T) {
	secret := "test-secret-key"
	agentID := uuid.New()

	token, err := IssueAgentToken(secret, agentID)
	if err != nil {
		t.Fatalf("IssueAgentToken: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	claims, err := ValidateAgentToken(secret, token)
	if err != nil {
		t.Fatalf("ValidateAgentToken: %v", err)
	}
	if claims.AgentID != agentID.String() {
		t.Errorf("AgentID = %q, want %q", claims.AgentID, agentID.String())
	}
	if claims.Subject != agentID.String() {
		t.Errorf("Subject = %q, want %q", claims.Subject, agentID.String())
	}
}

func TestAgentTokenRejectsUserJWT(t *testing.T) {
	secret := "test-secret-key"
	userID := uuid.New()

	// Issue a user token (no agent_id claim).
	userToken, err := IssueToken(secret, userID, "test@example.com", "admin")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	// ValidateAgentToken should reject it (missing agent_id).
	_, err = ValidateAgentToken(secret, userToken)
	if err == nil {
		t.Fatal("expected error validating user token as agent token")
	}
}

func TestAgentTokenRejectsWrongSecret(t *testing.T) {
	agentID := uuid.New()
	token, err := IssueAgentToken("secret-a", agentID)
	if err != nil {
		t.Fatalf("IssueAgentToken: %v", err)
	}

	_, err = ValidateAgentToken("secret-b", token)
	if err == nil {
		t.Fatal("expected error validating with wrong secret")
	}
}

func TestAgentMiddleware(t *testing.T) {
	secret := "test-secret-key"
	agentID := uuid.New()

	token, err := IssueAgentToken(secret, agentID)
	if err != nil {
		t.Fatalf("IssueAgentToken: %v", err)
	}

	t.Run("valid token", func(t *testing.T) {
		var gotAgentID uuid.UUID
		handler := AgentMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAgentID = AgentIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/api/agent/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if gotAgentID != agentID {
			t.Errorf("AgentIDFromContext = %v, want %v", gotAgentID, agentID)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		handler := AgentMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/api/agent/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		handler := AgentMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/api/agent/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("user token rejected", func(t *testing.T) {
		userToken, _ := IssueToken(secret, uuid.New(), "test@example.com", "admin")
		handler := AgentMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be called")
		}))

		req := httptest.NewRequest("GET", "/api/agent/test", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

func TestAgentIDFromContextNil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	id := AgentIDFromContext(req.Context())
	if id != uuid.Nil {
		t.Errorf("expected uuid.Nil, got %v", id)
	}
}
