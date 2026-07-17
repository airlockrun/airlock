package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/cors"
)

func TestPlatformCORSUsesExactPublicOrigin(t *testing.T) {
	handler := cors.Handler(platformCORSOptions("https://airlock.example.com"))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		origin string
		want   string
	}{
		{origin: "https://airlock.example.com", want: "https://airlock.example.com"},
		{origin: "https://agent.airlock.example.com"},
		{origin: "https://airlock.example.com.evil.test"},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://airlock.example.com/api/v1/me", nil)
			req.Header.Set("Origin", tc.origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.want {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, tc.want)
			}
		})
	}
}
