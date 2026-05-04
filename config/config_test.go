package config

import (
	"os"
	"testing"
)

// setRequiredEnv sets all required env vars for Load().
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("S3_URL", "http://localhost:9090")
	t.Setenv("S3_ACCESS_KEY", "minioadmin")
	t.Setenv("S3_SECRET_KEY", "minioadmin")
	// Subdomain routing is load-bearing — resolveAgentDomain panics if
	// neither AGENT_DOMAIN nor PUBLIC_URL is set, so seed one for tests.
	t.Setenv("AGENT_DOMAIN", "test.airlock.local")
}

func TestLoad(t *testing.T) {
	setRequiredEnv(t)

	c := Load()

	if c.DatabaseURL != "postgres://localhost/test" {
		t.Errorf("DatabaseURL = %q, want %q", c.DatabaseURL, "postgres://localhost/test")
	}
	if c.JWTSecret != "test-secret" {
		t.Errorf("JWTSecret = %q, want %q", c.JWTSecret, "test-secret")
	}
	if c.ServerAddr != ":8080" {
		t.Errorf("ServerAddr = %q, want %q", c.ServerAddr, ":8080")
	}
	if c.S3URL != "http://localhost:9090" {
		t.Errorf("S3URL = %q, want %q", c.S3URL, "http://localhost:9090")
	}
	if c.DBHost != "localhost" {
		t.Errorf("DBHost = %q, want %q", c.DBHost, "localhost")
	}
	if c.DBHostAgent != "postgres" {
		t.Errorf("DBHostAgent = %q, want %q", c.DBHostAgent, "postgres")
	}
	if c.OIDCEnabled() {
		t.Error("OIDCEnabled() = true, want false when env vars not set")
	}
}

func TestLoadCustomServerAddr(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SERVER_ADDR", ":9090")

	c := Load()
	if c.ServerAddr != ":9090" {
		t.Errorf("ServerAddr = %q, want %q", c.ServerAddr, ":9090")
	}
}

func TestLoadPanicsOnMissingDatabaseURL(t *testing.T) {
	setRequiredEnv(t)
	os.Unsetenv("DATABASE_URL")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for missing DATABASE_URL")
		}
		msg, ok := r.(string)
		if !ok || msg != "required environment variable DATABASE_URL is not set" {
			t.Errorf("unexpected panic message: %v", r)
		}
	}()
	Load()
}

func TestLoadPanicsOnMissingJWTSecret(t *testing.T) {
	setRequiredEnv(t)
	os.Unsetenv("JWT_SECRET")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for missing JWT_SECRET")
		}
	}()
	Load()
}

func TestLoadPanicsOnMissingEncryptionKey(t *testing.T) {
	setRequiredEnv(t)
	os.Unsetenv("ENCRYPTION_KEY")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for missing ENCRYPTION_KEY")
		}
	}()
	Load()
}

func TestLoadPanicsOnMissingS3URL(t *testing.T) {
	setRequiredEnv(t)
	os.Unsetenv("S3_URL")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for missing S3_URL")
		}
	}()
	Load()
}

func TestOIDCEnabled(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")
	t.Setenv("OIDC_CLIENT_ID", "my-client-id")

	c := Load()
	if !c.OIDCEnabled() {
		t.Error("OIDCEnabled() = false, want true when OIDC env vars are set")
	}
}
