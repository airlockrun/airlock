package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/airlockrun/agentsdk"
)

// DefaultAgentBuilderImage is the image tag airlock uses for the toolserver
// sandbox when AGENT_BUILDER_IMAGE is unset. Tag-pinning against
// agentsdk.Version ensures every airlock release references the matching
// toolserver build — drift between the two becomes impossible in prod.
const DefaultAgentBuilderImage = "agent-builder:v" + agentsdk.Version

type Config struct {
	// --- Core ---
	DatabaseURL string // Airlock's own Postgres connection
	JWTSecret   string
	ServerAddr  string

	// --- S3 / Object Storage ---
	// Three audiences: Airlock process, agent containers, public internet.
	S3URL       string // Airlock process → MinIO (e.g. "http://localhost:9090")
	S3URLAgent  string // Agent containers → MinIO via Docker network (e.g. "http://minio:9000")
	S3URLPublic string // Public internet → MinIO via reverse proxy (e.g. "https://s3.dev.airlock.run")
	S3AccessKey string
	S3SecretKey string
	S3Bucket    string
	S3Region    string

	// --- Database (agent schemas) ---
	// Airlock creates per-agent Postgres schemas. Connections are built from parts
	// because Airlock process and agent containers reach Postgres via different hosts.
	DBHost      string // Airlock process → Postgres (e.g. "localhost")
	DBHostAgent string // Agent containers → Postgres via Docker network (e.g. "postgres")
	DBPort      string
	DBName      string
	DBSSLMode   string // "disable" for dev, "require" for prod

	// --- Networking ---
	PublicURL     string // Public base URL (OAuth callbacks, auth links, e.g. "https://dev.airlock.run")
	APIURLAgent   string // Agent containers → Airlock API (e.g. "http://host.docker.internal:8080")
	AgentDomain   string // Subdomain routing (e.g. "dev.airlock.run" → {slug}.dev.airlock.run)
	DockerNetwork string // Docker network for agent containers (e.g. "airlock-dev")

	// --- Encryption ---
	// AES-256-GCM for provider API keys, webhook secrets, tokens at rest.
	// Generate with: openssl rand -hex 32
	EncryptionKey    string // hex-encoded 32-byte key (required)
	EncryptionKeyOld string // hex-encoded 32-byte key (optional, for rotation)

	// --- Containers ---
	ContainerRuntime string // "docker"
	ContainerImage   string // toolserver image name
	AnchorImage      string // anchor image name

	// --- Build pipeline ---
	AgentMonorepoPath string // local path to agent monorepo
	AgentBuilderImage string // toolserver sandbox image (default: agent-builder:v${agentsdk.Version})
	AgentBaseImage    string // agent runtime base image
	AgentRegistryURL  string // Docker registry for agent images (empty = local only)
	AgentLibsPath     string // path containing agentsdk/ and goai/ dirs (dev mode only)

	// --- Reverse proxy ---
	ReverseProxyTrustedProxies string // comma-separated CIDRs, "*" = trust all (default: trust none)
	ReverseProxyLimit          int    // how many proxy hops to trust in X-Forwarded-For (default: 1)

	// --- Optional ---
	WorkDir                string // temp directory for agent tool execution
	LLMProxyURL            string // route LLM calls through this proxy (e.g. telescope -watch)
	ActivationCodeFile     string // path to write the first-run activation code to (so `docker compose` users can `cat` it)
	ForceInlineAttachments bool   // dev escape hatch: force base64 delivery to LLMs even when the provider supports URLs (public URL unreachable from provider)

	// --- OIDC (optional) ---
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
}

func (c *Config) OIDCEnabled() bool {
	return c.OIDCIssuerURL != "" && c.OIDCClientID != ""
}

func Load() *Config {
	c := &Config{
		// Core
		DatabaseURL: requireEnv("DATABASE_URL"),
		JWTSecret:   requireEnv("JWT_SECRET"),
		ServerAddr:  envOr("SERVER_ADDR", ":8080"),

		// S3
		S3URL:       requireEnv("S3_URL"),
		S3URLAgent:  os.Getenv("S3_URL_AGENT"),
		S3URLPublic: os.Getenv("S3_URL_PUBLIC"),
		S3AccessKey: requireEnv("S3_ACCESS_KEY"),
		S3SecretKey: requireEnv("S3_SECRET_KEY"),
		S3Bucket:    envOr("S3_BUCKET", "airlock"),
		S3Region:    envOr("S3_REGION", "us-east-1"),

		// Database (agent schemas)
		DBHost:      envOr("DB_HOST", "localhost"),
		DBHostAgent: envOr("DB_HOST_AGENT", "postgres"),
		DBPort:      envOr("DB_PORT", "5432"),
		DBName:      envOr("DB_NAME", "airlock"),
		DBSSLMode:   envOr("DB_SSL_MODE", "require"),

		// Networking
		PublicURL:     envOr("PUBLIC_URL", "http://localhost:8080"),
		APIURLAgent:   envOr("API_URL_AGENT", "http://localhost:8080"),
		AgentDomain:   os.Getenv("AGENT_DOMAIN"),
		DockerNetwork: os.Getenv("DOCKER_NETWORK"),

		// Encryption
		EncryptionKey:    requireEnv("ENCRYPTION_KEY"),
		EncryptionKeyOld: os.Getenv("ENCRYPTION_KEY_OLD"),

		// Containers
		ContainerRuntime: envOr("CONTAINER_RUNTIME", "docker"),
		ContainerImage:   envOr("CONTAINER_IMAGE", "airlock-toolserver"),
		AnchorImage:      envOr("ANCHOR_IMAGE", "airlock-anchor"),

		// Build pipeline
		AgentMonorepoPath: envOr("AGENT_MONOREPO_PATH", "/var/lib/airlock/agents"),
		AgentBuilderImage: envOr("AGENT_BUILDER_IMAGE", DefaultAgentBuilderImage),
		AgentBaseImage:    envOr("AGENT_BASE_IMAGE", "airlock-agent-base"),
		AgentRegistryURL:  os.Getenv("AGENT_REGISTRY_URL"),
		AgentLibsPath:     os.Getenv("AGENT_LIBS_PATH"),

		// Reverse proxy
		ReverseProxyTrustedProxies: os.Getenv("REVERSE_PROXY_TRUSTED_PROXIES"),
		ReverseProxyLimit:          envIntOr("REVERSE_PROXY_LIMIT", 1),

		// Optional
		WorkDir:                envOr("WORK_DIR", "/tmp/airlock-spaces"),
		LLMProxyURL:            os.Getenv("LLM_PROXY_URL"),
		ActivationCodeFile:     envOr("ACTIVATION_CODE_FILE", "/var/lib/airlock/activation_code.txt"),
		ForceInlineAttachments: envBoolOr("FORCE_INLINE_ATTACHMENTS", false),

		// OIDC
		OIDCIssuerURL:    os.Getenv("OIDC_ISSUER_URL"),
		OIDCClientID:     os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),
	}
	return c
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		panic(fmt.Sprintf("environment variable %s: invalid integer %q", key, v))
	}
	return n
}

func envBoolOr(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		panic(fmt.Sprintf("environment variable %s: invalid bool %q", key, v))
	}
	return b
}
