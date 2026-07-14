package api

import (
	"net/http/httptest"
	"testing"
)

func TestSetAirlockSessionCookieSecure(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		forwarded string
		want      bool
	}{
		{"http", "http://localhost:42080", "", false},
		{"https", "https://airlock.example.com", "", true},
		{"forwarded https", "http://airlock:8080", "https", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.url, nil)
			if tt.forwarded != "" {
				r.Header.Set("X-Forwarded-Proto", tt.forwarded)
			}
			w := httptest.NewRecorder()
			setAirlockSessionCookie(w, r, "token")

			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("cookies = %v, want one", cookies)
			}
			if cookies[0].Secure != tt.want {
				t.Errorf("Secure = %t, want %t", cookies[0].Secure, tt.want)
			}
		})
	}
}
