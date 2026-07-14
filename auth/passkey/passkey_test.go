package passkey

import "testing"

func TestNew(t *testing.T) {
	tests := []struct {
		name       string
		publicURL  string
		wantRPID   string
		wantOrigin string
		wantErr    bool
	}{
		{"localhost dev", "http://localhost:8080", "localhost", "http://localhost:8080", false},
		{"local mode", "http://localhost:42080", "localhost", "http://localhost:42080", false},
		{"https host", "https://airlock.example.com", "airlock.example.com", "https://airlock.example.com", false},
		{"https host with port", "https://airlock.example.com:8443", "airlock.example.com", "https://airlock.example.com:8443", false},
		{"no host", "not-a-url", "", "", true},
		{"empty", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := New(tt.publicURL)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New(%q): expected error", tt.publicURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q): %v", tt.publicURL, err)
			}
			if w.Config.RPID != tt.wantRPID {
				t.Errorf("RPID = %q, want %q", w.Config.RPID, tt.wantRPID)
			}
			if len(w.Config.RPOrigins) != 1 || w.Config.RPOrigins[0] != tt.wantOrigin {
				t.Errorf("RPOrigins = %v, want [%q]", w.Config.RPOrigins, tt.wantOrigin)
			}
		})
	}
}
