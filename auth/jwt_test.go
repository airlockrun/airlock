package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testSecret = "test-secret-key"

func TestIssueAndValidateToken(t *testing.T) {
	userID := uuid.New()

	token, err := IssueToken(testSecret, userID, "test@example.com", "admin")
	if err != nil {
		t.Fatalf("IssueToken() error: %v", err)
	}

	claims, err := ValidateToken(testSecret, token)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}

	if claims.Subject != userID.String() {
		t.Errorf("Subject = %q, want %q", claims.Subject, userID.String())
	}
	if claims.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "test@example.com")
	}
	if claims.TenantRole != "admin" {
		t.Errorf("TenantRole = %q, want %q", claims.TenantRole, "admin")
	}
}

func TestValidateTokenRejectsTampered(t *testing.T) {
	userID := uuid.New()

	token, _ := IssueToken(testSecret, userID, "test@example.com", "admin")
	// Tamper with the payload (middle segment)
	parts := strings.SplitN(token, ".", 3)
	parts[1] = "eyJzdWIiOiJ0YW1wZXJlZCJ9" // {"sub":"tampered"}
	tampered := strings.Join(parts, ".")

	_, err := ValidateToken(testSecret, tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestValidateTokenRejectsWrongSecret(t *testing.T) {
	userID := uuid.New()

	token, _ := IssueToken(testSecret, userID, "test@example.com", "admin")

	_, err := ValidateToken("wrong-secret", token)
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestValidateTokenRejectsExpired(t *testing.T) {
	userID := uuid.New()

	// Create an already-expired token
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)),
		},
		Email:      "test@example.com",
		TenantRole: "admin",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(testSecret))

	_, err := ValidateToken(testSecret, signed)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestRefreshToken(t *testing.T) {
	userID := uuid.New()

	token, err := IssueRefreshToken(testSecret, userID, "test@example.com", "admin")
	if err != nil {
		t.Fatalf("IssueRefreshToken() error: %v", err)
	}

	claims, err := ValidateToken(testSecret, token)
	if err != nil {
		t.Fatalf("ValidateToken() error: %v", err)
	}

	// Refresh token should expire ~7 days from now
	exp := claims.ExpiresAt.Time
	diff := time.Until(exp)
	if diff < 6*24*time.Hour || diff > 8*24*time.Hour {
		t.Errorf("refresh token expiry = %v from now, want ~7 days", diff)
	}
}
