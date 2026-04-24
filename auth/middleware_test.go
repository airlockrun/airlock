package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
	token, _ := IssueToken(testSecret, userID, "test@example.com", "admin")

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

func TestRequireTenantRoleHierarchy(t *testing.T) {
	tests := []struct {
		name     string
		userRole string
		minRole  string
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
			token, _ := IssueToken(testSecret, userID, "test@example.com", tt.userRole)

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
