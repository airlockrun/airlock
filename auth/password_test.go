package auth

import "testing"

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := HashPassword("mypassword")
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	if err := CheckPassword(hash, "mypassword"); err != nil {
		t.Errorf("CheckPassword() should succeed for correct password: %v", err)
	}

	if err := CheckPassword(hash, "wrongpassword"); err == nil {
		t.Error("CheckPassword() should fail for wrong password")
	}
}

func TestHashPasswordDifferentOutputs(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("two hashes of the same password should differ (bcrypt uses random salt)")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		inputs   []string
		wantErr  bool
	}{
		{"empty", "", nil, true},
		{"common word", "password", nil, true},
		{"short alnum", "abc123", nil, true},
		{"sequential digits", "12345678", nil, true},
		{"contains own email", "alice@example.com", []string{"alice@example.com"}, true},
		{"long random", "a9f3c2e81b7d4056af12", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password, tt.inputs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePasswordStrength(%q) err=%v, wantErr=%v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestGenerateTempPassword(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		p, err := GenerateTempPassword()
		if err != nil {
			t.Fatalf("GenerateTempPassword: %v", err)
		}
		if len(p) < 16 {
			t.Fatalf("temp password too short (%d): %q", len(p), p)
		}
		if seen[p] {
			t.Fatalf("duplicate temp password: %q", p)
		}
		seen[p] = true
		// A generated temp password must clear the same strength bar real
		// passwords face, so the forced-change login it backs is consistent.
		if err := ValidatePasswordStrength(p, nil); err != nil {
			t.Fatalf("generated temp password is not strong enough: %q: %v", p, err)
		}
	}
}
