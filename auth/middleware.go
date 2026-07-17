package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
)

// Middleware validates the JWT Bearer token and injects claims into context.
// It returns 401 for missing, invalid, or expired tokens.
func Middleware(jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}
			token, ok := strings.CutPrefix(header, "Bearer ")
			if !ok || token == "" {
				http.Error(w, `{"error":"invalid authorization header"}`, http.StatusUnauthorized)
				return
			}

			claims, err := ValidateUserAccessToken(jwtSecret, token)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// Put claims on context — tenant package reads them
			ctx := r.Context()
			ctx = withClaims(ctx, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LiveSessionMiddleware verifies the active DB session and replaces token
// snapshots with the current user role and account-security state.
func LiveSessionMiddleware(database *db.DB) func(http.Handler) http.Handler {
	if database == nil {
		panic("auth: live session middleware db is required")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, `{"error":"not authenticated"}`, http.StatusUnauthorized)
				return
			}
			live, err := ResolveLiveUserClaims(r.Context(), dbq.New(database.Pool()), claims, true)
			if err != nil {
				http.Error(w, `{"error":"invalid or revoked session"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), live)))
		})
	}
}

// RequireRecentAuthentication protects credential mutations. Forced-password
// users may reach only the narrowly allowlisted account-securing operations.
func RequireRecentAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			http.Error(w, `{"error":"not authenticated"}`, http.StatusUnauthorized)
			return
		}
		if claims.MustChangePassword {
			next.ServeHTTP(w, r)
			return
		}
		if claims.AuthTime == nil || time.Since(claims.AuthTime.Time) > RecentAuthenticationWindow || claims.AuthTime.Time.After(time.Now().Add(time.Minute)) {
			http.Error(w, `{"error":"recent_authentication_required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
