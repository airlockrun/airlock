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

// TestIssueTokenHasNoClientID is the load-bearing invariant for the
// MCP endpoint's OAuth vs. web-login discrimination: web-login JWTs
// (IssueToken / IssueRefreshToken / IssueTokenWithDuration) must NEVER
// carry a client_id claim. If this test ever fails, the MCP endpoint
// would accept a regular user JWT as an OAuth access token and skip
// the aud + scope checks.
func TestIssueTokenHasNoClientID(t *testing.T) {
	userID := uuid.New()

	for name, issue := range map[string]func() (string, error){
		"IssueToken": func() (string, error) {
			return IssueToken(testSecret, userID, "x@y.z", "admin")
		},
		"IssueRefreshToken": func() (string, error) {
			return IssueRefreshToken(testSecret, userID, "x@y.z", "admin")
		},
		"IssueTokenWithDuration": func() (string, error) {
			return IssueTokenWithDuration(testSecret, userID, "x@y.z", "admin", time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			tok, err := issue()
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			c, err := ValidateToken(testSecret, tok)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			if c.ClientID != "" {
				t.Errorf("ClientID = %q, want empty", c.ClientID)
			}
			if c.Scope != "" {
				t.Errorf("Scope = %q, want empty", c.Scope)
			}
			if len(c.Audience) != 0 {
				t.Errorf("Audience = %v, want empty", c.Audience)
			}
		})
	}
}

func TestIssueOAuthAccessTokenCarriesClaims(t *testing.T) {
	userID := uuid.New()
	aud := "https://airlock.example.com/api/agent/abc/mcp"

	tok, err := IssueOAuthAccessToken(testSecret, userID, "x@y.z", "admin", "alk_pub_xyz", "mcp", aud)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	c, err := ValidateToken(testSecret, tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.ClientID != "alk_pub_xyz" {
		t.Errorf("ClientID = %q", c.ClientID)
	}
	if c.Scope != "mcp" {
		t.Errorf("Scope = %q", c.Scope)
	}
	if !AudienceContains(c.Audience, aud) {
		t.Errorf("AudienceContains(%v, %q) = false", c.Audience, aud)
	}
	if !ScopeContains(c.Scope, "mcp") {
		t.Errorf("ScopeContains(%q, mcp) = false", c.Scope)
	}
	if ScopeContains(c.Scope, "admin") {
		t.Errorf("ScopeContains(%q, admin) should be false", c.Scope)
	}
}

func TestScopeContainsMultiple(t *testing.T) {
	if !ScopeContains("mcp offline_access", "mcp") {
		t.Error("ScopeContains: should find 'mcp' in multi-scope")
	}
	if !ScopeContains("mcp offline_access", "offline_access") {
		t.Error("ScopeContains: should find 'offline_access' in multi-scope")
	}
	if ScopeContains("mcp", "") {
		t.Error("ScopeContains: empty required should be false")
	}
	if ScopeContains("", "mcp") {
		t.Error("ScopeContains: empty scope should be false")
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
