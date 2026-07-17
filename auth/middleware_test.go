package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMiddlewareNoHeader(t *testing.T) {
	handler := Middleware(testSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireRecentAuthentication(t *testing.T) {
	userID := uuid.New()
	tests := []struct {
		name       string
		authTime   time.Time
		mustChange bool
		want       int
	}{
		{name: "recent", authTime: time.Now(), want: http.StatusNoContent},
		{name: "stale", authTime: time.Now().Add(-RecentAuthenticationWindow - time.Minute), want: http.StatusForbidden},
		{name: "forced securing flow", authTime: time.Now().Add(-time.Hour), mustChange: true, want: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := IssueUserAccessToken(testSecret, userID, "test@example.com", "", "user", tt.mustChange, uuid.New(), 0, tt.authTime)
			if err != nil {
				t.Fatal(err)
			}
			handler := Middleware(testSecret)(RequireRecentAuthentication(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})))
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status=%d want=%d", rec.Code, tt.want)
			}
		})
	}
}

func TestMiddlewareInvalidToken(t *testing.T) {
	handler := Middleware(testSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareValidToken(t *testing.T) {
	userID := uuid.New()
	token, _ := IssueToken(testSecret, userID, "test@example.com", "", "admin", false)

	var gotClaims *Claims
	handler := Middleware(testSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotClaims == nil {
		t.Fatal("claims should be on context")
	}
	if gotClaims.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", gotClaims.Email, "test@example.com")
	}
}

func TestMiddlewareRejectsOtherTokenProfiles(t *testing.T) {
	userID := uuid.New()
	agentID := uuid.New()
	oauthToken, _ := IssueOAuthAccessToken(testSecret, userID, "test@example.com", "user", "client", "mcp", "https://example.test/mcp", 0)
	agentToken, _ := IssueAgentToken(testSecret, agentID, 1)
	subdomainToken, _ := IssueSubdomainToken(testSecret, agentID, userID, uuid.New(), "test@example.com", "", "user", 0)
	refreshToken, _ := IssueRefreshToken(testSecret, userID, "test@example.com", "", "user", false)

	for name, token := range map[string]string{
		"OAuth":     oauthToken,
		"agent":     agentToken,
		"subdomain": subdomainToken,
		"refresh":   refreshToken,
	} {
		t.Run(name, func(t *testing.T) {
			handler := Middleware(testSecret)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("handler should not be called")
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestRequireTenantRoleHierarchy(t *testing.T) {
	tests := []struct {
		name     string
		userRole string
		minRole  Role
		wantCode int
	}{
		{"admin passes admin check", "admin", "admin", http.StatusOK},
		{"admin passes manager check", "admin", "manager", http.StatusOK},
		{"admin passes user check", "admin", "user", http.StatusOK},
		{"manager passes manager check", "manager", "manager", http.StatusOK},
		{"manager passes user check", "manager", "user", http.StatusOK},
		{"manager blocked by admin check", "manager", "admin", http.StatusForbidden},
		{"user passes user check", "user", "user", http.StatusOK},
		{"user blocked by manager check", "user", "manager", http.StatusForbidden},
		{"user blocked by admin check", "user", "admin", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID := uuid.New()
			token, _ := IssueToken(testSecret, userID, "test@example.com", "", tt.userRole, false)

			handler := Middleware(testSecret)(RequireTenantRole(tt.minRole)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("role=%q minRole=%q: got status %d, want %d", tt.userRole, tt.minRole, rec.Code, tt.wantCode)
			}
		})
	}
}
