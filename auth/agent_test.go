package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type testAgentTokenQuerier struct {
	state dbq.GetAgentTokenAuthRow
	err   error
}

func (q testAgentTokenQuerier) GetAgentTokenAuth(context.Context, pgtype.UUID) (dbq.GetAgentTokenAuthRow, error) {
	return q.state, q.err
}

func liveAgentTokenQuerier(version int64) testAgentTokenQuerier {
	return testAgentTokenQuerier{state: dbq.GetAgentTokenAuthRow{Status: "active", AgentTokenVersion: version}}
}

func TestIssueAndValidateAgentToken(t *testing.T) {
	secret := "test-secret-key"
	agentID := uuid.New()

	token, err := IssueAgentToken(secret, agentID, 7)
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
	if claims.Profile != agentTokenProfile || claims.TokenVersion != 7 {
		t.Errorf("profile/version = %q/%d, want %q/7", claims.Profile, claims.TokenVersion, agentTokenProfile)
	}
	if ttl := time.Until(claims.ExpiresAt.Time); ttl < AgentTokenDuration-time.Minute || ttl > AgentTokenDuration+time.Minute {
		t.Errorf("token TTL = %v, want about %v", ttl, AgentTokenDuration)
	}
}

func TestAgentTokenRejectsUserJWT(t *testing.T) {
	secret := "test-secret-key"
	userID := uuid.New()

	// Issue a user token (no agent_id claim).
	userToken, err := IssueToken(secret, userID, "test@example.com", "Test User", "admin", false)
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
	token, err := IssueAgentToken("secret-a", agentID, 1)
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

	token, err := IssueAgentToken(secret, agentID, 1)
	if err != nil {
		t.Fatalf("IssueAgentToken: %v", err)
	}

	t.Run("valid token", func(t *testing.T) {
		var gotAgentID uuid.UUID
		handler := AgentMiddleware(secret, liveAgentTokenQuerier(1))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		handler := AgentMiddleware(secret, liveAgentTokenQuerier(1))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		handler := AgentMiddleware(secret, liveAgentTokenQuerier(1))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		userToken, _ := IssueToken(secret, uuid.New(), "test@example.com", "", "admin", false)
		handler := AgentMiddleware(secret, liveAgentTokenQuerier(1))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	t.Run("OAuth and subdomain tokens rejected", func(t *testing.T) {
		userID := uuid.New()
		oauthToken, _ := IssueOAuthAccessToken(secret, userID, "test@example.com", "user", "client", "mcp", "https://example.test/mcp", 0)
		subdomainToken, _ := IssueSubdomainToken(secret, agentID, userID, uuid.New(), "test@example.com", "", "user", 0)
		for name, token := range map[string]string{"OAuth": oauthToken, "subdomain": subdomainToken} {
			t.Run(name, func(t *testing.T) {
				handler := AgentMiddleware(secret, liveAgentTokenQuerier(1))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("handler should not be called")
				}))
				req := httptest.NewRequest(http.MethodGet, "/api/agent/test", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
				}
			})
		}
	})
}

func TestAgentMiddlewareRejectsRevokedOrInactiveAgent(t *testing.T) {
	secret := "test-secret-key"
	agentID := uuid.New()
	token, err := IssueAgentToken(secret, agentID, 3)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		query testAgentTokenQuerier
	}{
		{name: "cross version", query: liveAgentTokenQuerier(4)},
		{name: "stopped", query: testAgentTokenQuerier{state: dbq.GetAgentTokenAuthRow{Status: "stopped", AgentTokenVersion: 3}}},
		{name: "deleted", query: testAgentTokenQuerier{err: errors.New("not found")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := AgentMiddleware(secret, tt.query)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("handler should not be called")
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/agent/test", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestValidateAgentTokenRejectsMissingCurrentProfile(t *testing.T) {
	agentID := uuid.New()
	now := time.Now()
	claims := AgentClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: agentTokenIssuer, Subject: agentID.String(),
			Audience: jwt.ClaimStrings{agentTokenAudience},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		AgentID: agentID.String(), TokenUse: tokenUseAgent, TokenVersion: 1,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAgentToken("test-secret-key", token); err == nil {
		t.Fatal("token without the current profile was accepted")
	}
}

func TestAgentIDFromContextNil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	id := AgentIDFromContext(req.Context())
	if id != uuid.Nil {
		t.Errorf("expected uuid.Nil, got %v", id)
	}
}
