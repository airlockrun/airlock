package config

import (
	"net/netip"
	"os"
	"testing"
)

func TestParseSizeBytes(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"   ", 0},
		{"1024", 1024},
		{"512m", 512 << 20},
		{"512mb", 512 << 20},
		{"2g", 2 << 30},
		{"2GB", 2 << 30},
		{"4k", 4 << 10},
		{"100b", 100},
		{"garbage", 0},
		{"-5m", 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := parseSizeBytes(tt.in); got != tt.want {
				t.Errorf("parseSizeBytes(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestResolveAgentRuntime(t *testing.T) {
	tests := []struct {
		env  string
		want string
	}{
		{"", ""},
		{"runc", ""},
		{"default", ""},
		{"gvisor", "runsc"},
		{"GVISOR", "runsc"},
		{"runsc", "runsc"},
		{"my-custom-runtime", "my-custom-runtime"},
	}
	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			t.Setenv("AGENT_SANDBOX", tt.env)
			if got := resolveAgentRuntime(); got != tt.want {
				t.Errorf("resolveAgentRuntime() with AGENT_SANDBOX=%q = %q, want %q", tt.env, got, tt.want)
			}
		})
	}
}

// setRequiredEnv sets all required env vars for Load().
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("S3_URL", "http://localhost:9090")
	t.Setenv("S3_ACCESS_KEY", "minioadmin")
	t.Setenv("S3_SECRET_KEY", "minioadmin")
	t.Setenv("AIRLOCK_INSTANCE_ID", "airlock")
	t.Setenv("REVERSE_PROXY_AUTH_SECRET", "test-reverse-proxy-auth-secret-32-bytes")
	t.Setenv("AGENT_NETWORK_PER_AGENT", "false")
	// Subdomain routing is load-bearing — resolveAgentDomain panics if
	// neither AGENT_DOMAIN nor PUBLIC_URL is set, so seed one for tests.
	t.Setenv("AGENT_DOMAIN", "test.airlock.local")
}

func TestAgentNetworkFallback(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("DOCKER_NETWORK", "airlock-dev")

	// AGENT_NETWORK unset → falls back to DOCKER_NETWORK (dev behaviour).
	t.Setenv("AGENT_NETWORK", "")
	if c := Load(); c.AgentNetwork != "airlock-dev" {
		t.Errorf("AgentNetwork (unset) = %q, want airlock-dev", c.AgentNetwork)
	}

	// AGENT_NETWORK set → used verbatim (prod isolation).
	t.Setenv("AGENT_NETWORK", "agents")
	if c := Load(); c.AgentNetwork != "agents" {
		t.Errorf("AgentNetwork (set) = %q, want agents", c.AgentNetwork)
	}
}

func TestAgentNetworkPerAgent(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("DOCKER_NETWORK", "airlock")
	t.Setenv("AGENT_NETWORK", "airlock-agents")
	t.Setenv("AGENT_NETWORK_PER_AGENT", "true")
	if c := Load(); !c.AgentNetworkPerAgent {
		t.Fatal("AgentNetworkPerAgent = false, want true")
	}
}

func TestAgentNetworkPerAgentRequiresSeedNetwork(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("DOCKER_NETWORK", "")
	t.Setenv("AGENT_NETWORK", "")
	t.Setenv("AGENT_NETWORK_PER_AGENT", "true")
	defer func() {
		if recover() == nil {
			t.Fatal("Load did not panic without AGENT_NETWORK")
		}
	}()
	Load()
}

func TestAgentDatabasePort(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("DB_PORT", "6432")
	if c := Load(); c.DBPortAgent != "6432" {
		t.Fatalf("DBPortAgent without override = %q, want 6432", c.DBPortAgent)
	}
	t.Setenv("DB_PORT_AGENT", "5432")
	if c := Load(); c.DBPortAgent != "5432" {
		t.Fatalf("DBPortAgent with override = %q, want 5432", c.DBPortAgent)
	}
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
	if c.DBPortAgent != "5432" {
		t.Errorf("DBPortAgent = %q, want %q", c.DBPortAgent, "5432")
	}
	if c.ReverseProxyAuthSecret != "test-reverse-proxy-auth-secret-32-bytes" {
		t.Errorf("ReverseProxyAuthSecret = %q", c.ReverseProxyAuthSecret)
	}
	if c.ReverseProxyTrustedPeers != defaultTrustedProxyPeers {
		t.Errorf("ReverseProxyTrustedPeers = %q, want %q", c.ReverseProxyTrustedPeers, defaultTrustedProxyPeers)
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

func TestLoadAgentHostGateway(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("AGENT_HOST_GATEWAY", "true")
	if c := Load(); !c.AgentHostGateway {
		t.Error("AgentHostGateway = false, want true")
	}
}

func TestLoadAgentHTTPPrivateCIDRs(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("AGENT_HTTP_PRIVATE_CIDRS", "10.0.0.0/8,100.64.0.0/10")

	got := Load().AgentHTTPPrivateCIDRs
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
	}
	if len(got) != len(want) {
		t.Fatalf("AgentHTTPPrivateCIDRs has %d prefixes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AgentHTTPPrivateCIDRs[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestParseCIDREnv(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		const key = "AIRLOCK_TEST_DEFAULT_CIDRS"
		got := parseCIDREnv(key, "0.0.0.0/0, ::/0")
		want := []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
		if len(got) != len(want) {
			t.Fatalf("parseCIDREnv() returned %d prefixes, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("parseCIDREnv()[%d] = %s, want %s", i, got[i], want[i])
			}
		}
	})

	t.Run("explicit empty", func(t *testing.T) {
		const key = "AIRLOCK_TEST_EMPTY_CIDRS"
		t.Setenv(key, "")
		if got := parseCIDREnv(key, defaultAgentHTTPPrivateCIDRs); len(got) != 0 {
			t.Fatalf("parseCIDREnv() returned %v, want no prefixes", got)
		}
	})

	t.Run("canonicalizes", func(t *testing.T) {
		const key = "AIRLOCK_TEST_MASKED_CIDRS"
		t.Setenv(key, "192.168.1.42/24")
		got := parseCIDREnv(key, "")
		want := netip.MustParsePrefix("192.168.1.0/24")
		if len(got) != 1 || got[0] != want {
			t.Fatalf("parseCIDREnv() = %v, want [%s]", got, want)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		const key = "AIRLOCK_TEST_INVALID_CIDRS"
		t.Setenv(key, "192.168.1.0/24,not-a-cidr")
		defer func() {
			if recover() == nil {
				t.Fatal("parseCIDREnv() did not panic")
			}
		}()
		parseCIDREnv(key, "")
	})
}

func TestLocalAgentBaseURL(t *testing.T) {
	c := &Config{
		AgentScheme: "http",
		AgentPort:   "42080",
		AgentDomain: "localhost",
	}
	if got, want := c.AgentBaseURL("notes"), "http://notes.localhost:42080"; got != want {
		t.Errorf("AgentBaseURL() = %q, want %q", got, want)
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

func TestLoadPanicsOnMissingInstanceID(t *testing.T) {
	setRequiredEnv(t)
	os.Unsetenv("AIRLOCK_INSTANCE_ID")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for missing AIRLOCK_INSTANCE_ID")
		}
		msg, ok := r.(string)
		if !ok || msg != "required environment variable AIRLOCK_INSTANCE_ID is not set" {
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

func TestLoadEncryptionKeyRewrapDefaultsFalse(t *testing.T) {
	setRequiredEnv(t)
	os.Unsetenv("ENCRYPTION_KEY_REWRAP")
	if Load().EncryptionKeyRewrap {
		t.Fatal("EncryptionKeyRewrap defaults true")
	}
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

func TestValidateDeployment(t *testing.T) {
	const (
		strongJWT = "0123456789abcdef0123456789abcdef"
		devKey    = "00000000000000000000000000000000000000000000000000000000deadbeef"
	)
	tests := []struct {
		name      string
		publicURL string
		tlsMode   string
		jwt       string
		key       string
		panics    bool
	}{
		{"local development secrets", "http://localhost:8080", "local", "dev", devKey, false},
		{"loopback address", "http://127.0.0.1:8080", "", "dev", devKey, false},
		{"production https", "https://airlock.example.com", "wildcard", strongJWT, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"proxy with exact trust", "https://airlock.example.com", "proxy", strongJWT, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"public URL path", "https://airlock.example.com/app", "wildcard", strongJWT, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"production http", "http://airlock.example.com", "proxy", strongJWT, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"local mode on public host", "https://airlock.example.com", "local", strongJWT, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"short production jwt", "https://airlock.example.com", "manual", "short", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"development encryption key in production", "https://airlock.example.com", "tunnel", strongJWT, devKey, true},
		{"unknown tls mode", "https://airlock.example.com", "magic", strongJWT, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trusted := ""
			if tt.name == "proxy with exact trust" {
				trusted = "10.0.0.5/32"
			}
			c := &Config{
				PublicURL:                tt.publicURL,
				TLSMode:                  tt.tlsMode,
				JWTSecret:                tt.jwt,
				EncryptionKey:            tt.key,
				ReverseProxyAuthSecret:   "test-reverse-proxy-auth-secret-32-bytes",
				ReverseProxyTrustedPeers: defaultTrustedProxyPeers,
				ReverseProxyLimit:        1,
				CaddyTrustedProxies:      trusted,
			}
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				validateDeployment(c)
			}()
			if panicked != tt.panics {
				t.Fatalf("validateDeployment() panicked = %v, want %v", panicked, tt.panics)
			}
		})
	}
}

func TestValidateDeploymentRejectsUnsafeProxyTrust(t *testing.T) {
	for _, trusted := range []string{"", "*", "0.0.0.0/0", "::/0", "not-a-cidr"} {
		t.Run(trusted, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("validateDeployment accepted proxy trust %q", trusted)
				}
			}()
			validateDeployment(&Config{
				PublicURL:                "https://airlock.example.com",
				TLSMode:                  "proxy",
				JWTSecret:                "0123456789abcdef0123456789abcdef",
				EncryptionKey:            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				ReverseProxyAuthSecret:   "test-reverse-proxy-auth-secret-32-bytes",
				ReverseProxyTrustedPeers: defaultTrustedProxyPeers,
				ReverseProxyLimit:        1,
				CaddyTrustedProxies:      trusted,
			})
		})
	}
}

func TestValidateDeploymentRejectsUnsafeProxyAuthentication(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		peers  string
		limit  int
	}{
		{"short secret", "short", defaultTrustedProxyPeers, 1},
		{"missing peers", "test-reverse-proxy-auth-secret-32-bytes", "", 1},
		{"wildcard peer", "test-reverse-proxy-auth-secret-32-bytes", "0.0.0.0/0", 1},
		{"invalid peer", "test-reverse-proxy-auth-secret-32-bytes", "not-a-cidr", 1},
		{"invalid limit", "test-reverse-proxy-auth-secret-32-bytes", defaultTrustedProxyPeers, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("validateDeployment accepted unsafe proxy authentication")
				}
			}()
			validateDeployment(&Config{
				PublicURL:                "http://localhost:8080",
				EncryptionKey:            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				ReverseProxyAuthSecret:   tt.secret,
				ReverseProxyTrustedPeers: tt.peers,
				ReverseProxyLimit:        tt.limit,
			})
		})
	}
}

func TestValidateDeploymentRewrapRequiresOldKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("validateDeployment accepted key rotation without an old key")
		}
	}()
	validateDeployment(&Config{
		PublicURL:                "http://localhost:8080",
		EncryptionKey:            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ReverseProxyAuthSecret:   "test-reverse-proxy-auth-secret-32-bytes",
		ReverseProxyTrustedPeers: defaultTrustedProxyPeers,
		ReverseProxyLimit:        1,
		EncryptionKeyRewrap:      true,
	})
}

func TestValidateDeploymentRejectsDuplicateOldKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("validateDeployment accepted the active key as the old key")
		}
	}()
	validateDeployment(&Config{
		PublicURL:                "http://localhost:8080",
		EncryptionKey:            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EncryptionKeyOld:         "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ReverseProxyAuthSecret:   "test-reverse-proxy-auth-secret-32-bytes",
		ReverseProxyTrustedPeers: defaultTrustedProxyPeers,
		ReverseProxyLimit:        1,
	})
}

func TestValidateDeploymentAllowsKeyRotation(t *testing.T) {
	validateDeployment(&Config{
		PublicURL:                "http://localhost:8080",
		EncryptionKey:            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EncryptionKeyOld:         "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		ReverseProxyAuthSecret:   "test-reverse-proxy-auth-secret-32-bytes",
		ReverseProxyTrustedPeers: defaultTrustedProxyPeers,
		ReverseProxyLimit:        1,
		EncryptionKeyRewrap:      true,
	})
}
