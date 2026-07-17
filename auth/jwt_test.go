package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testSecret = "test-secret-key"

func TestIssueAndValidateToken(t *testing.T) {
	userID := uuid.New()

	token, err := IssueToken(testSecret, userID, "test@example.com", "", "admin", false)
	if err != nil {
		t.Fatalf("IssueToken() error: %v", err)
	}

	claims, err := ValidateUserAccessToken(testSecret, token)
	if err != nil {
		t.Fatalf("ValidateUserAccessToken() error: %v", err)
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
	if claims.SessionID == "" || claims.AuthTime == nil {
		t.Errorf("session claims missing: sid=%q auth_time=%v", claims.SessionID, claims.AuthTime)
	}
}

func TestValidateTokenRejectsTampered(t *testing.T) {
	userID := uuid.New()

	token, _ := IssueToken(testSecret, userID, "test@example.com", "", "admin", false)
	// Tamper with the payload (middle segment)
	parts := strings.SplitN(token, ".", 3)
	parts[1] = "eyJzdWIiOiJ0YW1wZXJlZCJ9" // {"sub":"tampered"}
	tampered := strings.Join(parts, ".")

	_, err := ValidateUserAccessToken(testSecret, tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestValidateTokenRejectsWrongSecret(t *testing.T) {
	userID := uuid.New()

	token, _ := IssueToken(testSecret, userID, "test@example.com", "", "admin", false)

	_, err := ValidateUserAccessToken("wrong-secret", token)
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

	_, err := ValidateUserAccessToken(testSecret, signed)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

// TestIssueTokenHasNoClientID pins the user-access profile shape.
func TestIssueTokenHasNoClientID(t *testing.T) {
	userID := uuid.New()

	for name, issue := range map[string]func() (string, error){
		"IssueToken": func() (string, error) {
			return IssueToken(testSecret, userID, "x@y.z", "", "admin", false)
		},
	} {
		t.Run(name, func(t *testing.T) {
			tok, err := issue()
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			c, err := ValidateUserAccessToken(testSecret, tok)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			if c.ClientID != "" {
				t.Errorf("ClientID = %q, want empty", c.ClientID)
			}
			if c.Scope != "" {
				t.Errorf("Scope = %q, want empty", c.Scope)
			}
			if len(c.Audience) != 1 || c.Audience[0] != userTokenAudience {
				t.Errorf("Audience = %v, want [%q]", c.Audience, userTokenAudience)
			}
		})
	}
}

func TestIssueOAuthAccessTokenCarriesClaims(t *testing.T) {
	userID := uuid.New()
	aud := "https://airlock.example.com/api/agent/abc/mcp"

	tok, err := IssueOAuthAccessToken(testSecret, userID, "x@y.z", "admin", "alk_pub_xyz", "mcp", aud, 7)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	c, err := ValidateOAuthAccessToken(testSecret, tok, aud)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.ClientID != "alk_pub_xyz" {
		t.Errorf("ClientID = %q", c.ClientID)
	}
	if c.Scope != "mcp" {
		t.Errorf("Scope = %q", c.Scope)
	}
	if c.AuthEpoch != 7 {
		t.Errorf("AuthEpoch = %d, want 7", c.AuthEpoch)
	}
	if len(c.Audience) != 1 || c.Audience[0] != aud {
		t.Errorf("Audience = %v, want [%q]", c.Audience, aud)
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

	token, err := IssueRefreshToken(testSecret, userID, "test@example.com", "", "admin", false)
	if err != nil {
		t.Fatalf("IssueRefreshToken() error: %v", err)
	}

	claims, err := ValidateRefreshToken(testSecret, token)
	if err != nil {
		t.Fatalf("ValidateRefreshToken() error: %v", err)
	}

	// Refresh token should expire ~7 days from now
	exp := claims.ExpiresAt.Time
	diff := time.Until(exp)
	if diff < 6*24*time.Hour || diff > 8*24*time.Hour {
		t.Errorf("refresh token expiry = %v from now, want ~7 days", diff)
	}
}

func TestTokenProfileSeparation(t *testing.T) {
	userID := uuid.New()
	agentID := uuid.New()
	oauthAudience := "https://airlock.example.com/api/agent/" + agentID.String() + "/mcp"

	userToken, err := IssueToken(testSecret, userID, "user@example.com", "User", "user", false)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	oauthToken, err := IssueOAuthAccessToken(testSecret, userID, "user@example.com", "user", "client", "mcp", oauthAudience, 0)
	if err != nil {
		t.Fatalf("IssueOAuthAccessToken: %v", err)
	}
	agentToken, err := IssueAgentToken(testSecret, agentID, 1)
	if err != nil {
		t.Fatalf("IssueAgentToken: %v", err)
	}
	subdomainToken, err := IssueSubdomainToken(testSecret, agentID, userID, uuid.New(), "user@example.com", "User", "user", 0)
	if err != nil {
		t.Fatalf("IssueSubdomainToken: %v", err)
	}
	refreshToken, err := IssueRefreshToken(testSecret, userID, "user@example.com", "User", "user", false)
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}

	tokens := map[string]string{
		"user":      userToken,
		"oauth":     oauthToken,
		"agent":     agentToken,
		"subdomain": subdomainToken,
		"refresh":   refreshToken,
	}
	validators := map[string]func(string) error{
		"user": func(token string) error {
			_, err := ValidateUserAccessToken(testSecret, token)
			return err
		},
		"oauth": func(token string) error {
			_, err := ValidateOAuthAccessToken(testSecret, token, oauthAudience)
			return err
		},
		"agent": func(token string) error {
			_, err := ValidateAgentToken(testSecret, token)
			return err
		},
		"subdomain": func(token string) error {
			_, err := ValidateSubdomainToken(testSecret, token, agentID)
			return err
		},
		"refresh": func(token string) error {
			_, err := ValidateRefreshToken(testSecret, token)
			return err
		},
	}
	for validatorName, validate := range validators {
		for tokenName, token := range tokens {
			t.Run(validatorName+" rejects "+tokenName, func(t *testing.T) {
				err := validate(token)
				if tokenName == validatorName && err != nil {
					t.Fatalf("matching profile rejected: %v", err)
				}
				if tokenName != validatorName && err == nil {
					t.Fatal("cross-profile token accepted")
				}
			})
		}
	}

	if _, err := ValidateSubdomainToken(testSecret, subdomainToken, uuid.New()); err == nil {
		t.Fatal("subdomain token accepted for a different agent")
	}
	subdomainClaims, err := ValidateSubdomainToken(testSecret, subdomainToken, agentID)
	if err != nil {
		t.Fatalf("ValidateSubdomainToken: %v", err)
	}
	if ttl := time.Until(subdomainClaims.ExpiresAt.Time); ttl < 55*time.Minute || ttl > 65*time.Minute {
		t.Errorf("subdomain token TTL = %v, want about one hour", ttl)
	}
	if _, err := uuid.Parse(subdomainClaims.SessionID); err != nil {
		t.Fatalf("subdomain token sid = %q: %v", subdomainClaims.SessionID, err)
	}
	if _, err := ValidateOAuthAccessToken(testSecret, oauthToken, oauthAudience+"/other"); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("OAuth token wrong audience error = %v, want ErrInvalidAudience", err)
	}
}

func TestIssueSubdomainTokenRequiresSessionID(t *testing.T) {
	if _, err := IssueSubdomainToken(testSecret, uuid.New(), uuid.New(), uuid.Nil, "user@example.com", "User", "user", 0); err == nil {
		t.Fatal("IssueSubdomainToken accepted a nil session ID")
	}
}

func TestTokenValidatorsRequireExactHS256(t *testing.T) {
	userID := uuid.New()
	agentID := uuid.New()
	oauthAudience := "https://example.test/mcp"
	userToken, _ := IssueToken(testSecret, userID, "user@example.com", "User", "user", false)
	oauthToken, _ := IssueOAuthAccessToken(testSecret, userID, "user@example.com", "user", "client", "mcp", oauthAudience, 0)
	agentToken, _ := IssueAgentToken(testSecret, agentID, 1)
	subdomainToken, _ := IssueSubdomainToken(testSecret, agentID, userID, uuid.New(), "user@example.com", "User", "user", 0)
	refreshToken, _ := IssueRefreshToken(testSecret, userID, "user@example.com", "User", "user", false)

	tests := []struct {
		name     string
		token    string
		claims   jwt.Claims
		validate func(string) error
	}{
		{name: "user", token: userToken, claims: &Claims{}, validate: func(token string) error {
			_, err := ValidateUserAccessToken(testSecret, token)
			return err
		}},
		{name: "OAuth", token: oauthToken, claims: &Claims{}, validate: func(token string) error {
			_, err := ValidateOAuthAccessToken(testSecret, token, oauthAudience)
			return err
		}},
		{name: "agent", token: agentToken, claims: &AgentClaims{}, validate: func(token string) error {
			_, err := ValidateAgentToken(testSecret, token)
			return err
		}},
		{name: "subdomain", token: subdomainToken, claims: &Claims{}, validate: func(token string) error {
			_, err := ValidateSubdomainToken(testSecret, token, agentID)
			return err
		}},
		{name: "refresh", token: refreshToken, claims: &Claims{}, validate: func(token string) error {
			_, err := ValidateRefreshToken(testSecret, token)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := jwt.NewParser().ParseUnverified(tt.token, tt.claims); err != nil {
				t.Fatalf("parse issued token: %v", err)
			}
			signed, err := jwt.NewWithClaims(jwt.SigningMethodHS384, tt.claims).SignedString([]byte(testSecret))
			if err != nil {
				t.Fatalf("sign HS384 token: %v", err)
			}
			if err := tt.validate(signed); err == nil {
				t.Fatal("HS384 token accepted")
			}
		})
	}
}
