package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/airlockrun/airlock"
)

// Default toolserver/runtime images. Pinned to airlock.Version so every airlock
// release references the matched pair built+published by the same release tag —
// drift becomes impossible in prod. Self-host operators can still override via
// AGENT_BUILDER_IMAGE / AGENT_BASE_IMAGE if they need a custom build.
const (
	DefaultAgentBuilderImage = "ghcr.io/airlockrun/airlock-agent-builder:v" + airlock.Version
	DefaultAgentBaseImage    = "ghcr.io/airlockrun/airlock-agent-base:v" + airlock.Version
)

type Config struct {
	// --- Core ---
	DatabaseURL string // Airlock's own Postgres connection
	JWTSecret   string
	ServerAddr  string

	// --- S3 / Object Storage ---
	// Two audiences: Airlock process and public internet. Agents never hit
	// S3 directly — their storage goes through airlock's /api/agent/storage
	// API, and presigned shares use S3URLPublic over internet egress.
	S3URL       string // Airlock process → MinIO (e.g. "http://localhost:9090")
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
	PublicURL   string // Public base URL (OAuth callbacks, auth links, e.g. "https://dev.airlock.run")
	APIURLAgent string // Agent containers → Airlock API (e.g. "http://host.docker.internal:8080"). Intentionally independent of PublicURL/AgentDomain — it's the internal container→airlock callback, not a public URL.
	AgentDomain string // Subdomain routing (e.g. "dev.airlock.run" → {slug}.dev.airlock.run)
	// AgentScheme/AgentPort are derived once from PublicURL (see Load).
	// Together with AgentDomain they form the single source of truth for
	// per-agent external route URLs — use AgentBaseURL(slug), never
	// re-derive these elsewhere.
	AgentScheme   string // "http" | "https"
	AgentPort     string // explicit non-default port, else ""
	DockerNetwork string // Docker network for infra + toolserver/build containers (e.g. "airlock-dev")
	// AgentNetwork is the Docker network agent RUNTIME containers attach to.
	// Defaults to DockerNetwork when AGENT_NETWORK is unset. Prod sets it to
	// an isolated network carrying only airlock + postgres (not rustfs/caddy/
	// frontend) so a malicious agent can't reach infra services it doesn't
	// need. See docs/agent-isolation.md.
	AgentNetwork string

	// --- Encryption ---
	// AES-256-GCM for provider API keys, webhook secrets, tokens at rest.
	// Generate with: openssl rand -hex 32
	EncryptionKey    string // hex-encoded 32-byte key (required)
	EncryptionKeyOld string // hex-encoded 32-byte key (optional, for rotation)

	// --- Containers ---
	ContainerRuntime string // "docker"
	ContainerImage   string // toolserver image name

	// AgentRuntime is the OCI runtime for agent containers — "" = the
	// Docker default (runc), "runsc" = gVisor. Set via AGENT_SANDBOX
	// (gvisor → runsc). The HostConfig hardening (cap drop, no-new-privs,
	// limits) applies on either runtime; gVisor adds a userspace-kernel
	// sandbox on top.
	AgentRuntime string
	// AgentMemoryLimitBytes caps each agent container's memory (0 =
	// unlimited). Optional because the host's size is unknown; OomScoreAdj
	// makes agents the first OOM victim regardless, so the host survives
	// collective pressure without a per-agent cap. Set via
	// AGENT_MEMORY_LIMIT (e.g. "512m", "2g").
	AgentMemoryLimitBytes int64

	// --- Build pipeline ---
	// AgentReposPath is the base directory holding per-agent git repos.
	// Each agent's source lives at <AgentReposPath>/<agentID>/ with its
	// own .git/. The 003_split_monorepo migration moves any pre-multirepo
	// install (single monorepo with agents/{id}/ subdirs) from the legacy
	// AGENT_MONOREPO_PATH location into this layout on first startup
	// after upgrade.
	AgentReposPath    string
	AgentBuilderImage string // toolserver sandbox image (default: DefaultAgentBuilderImage)
	AgentBaseImage    string // agent runtime base image
	AgentRegistryURL  string // Docker registry for agent images (empty = local only)
	// BuildkitHost, when set (e.g. unix:///run/buildkit/buildkitd.sock),
	// routes agent image builds through a remote buildx builder backed by a
	// rootless buildkitd — so the agent's untrusted setup.sh runs as root
	// inside buildkitd (unprivileged on the host), not on the host's root
	// dockerd. Empty = legacy `docker build` on the host daemon (dev).
	BuildkitHost      string
	AgentLibsPath     string // path containing agentsdk/ goai/ sol/ dirs (the libs we own). Set after startup either to the user-supplied AGENT_LIBS_PATH (dev) or the extracted cache dir (prod). Always non-empty by the time the build pipeline runs.
	AgentLibsExtPath  string // path containing goose/ templ/ dirs (third-party libs always sourced from the agent-builder image's baked /libs/). Set at startup by EnsureLibs; not read from env.
	AgentLibsCacheDir string // base dir where extracted /libs/ from agent-builder image is cached. Subdir per image digest.

	// AgentLibsPathExplicit is true iff the operator set AGENT_LIBS_PATH as
	// an env var (i.e. dev mode, where AgentLibsPath points at a live source
	// tree we want overlaid into toolservers). False in prod (where
	// AgentLibsPath holds the extracted cache dir, used only for the
	// per-agent docker build's --build-context — overlaying the extracted
	// cache onto the toolserver's image-baked /libs/ would just mask the
	// authoritative content with itself, and risks shadowing files if the
	// extraction is mid-way or partial).
	AgentLibsPathExplicit bool

	// AgentCodegenPath is where the build pipeline creates per-build temp
	// directories for sparse checkouts and cache-warming scaffolds.
	// AgentCodegenVolume is the Docker volume name that contains
	// AgentCodegenPath and is also mounted into spawned sibling
	// containers — required for docker-in-docker (airlock-in-container)
	// deployments where bind-mounts of host paths don't work because
	// airlock's filesystem is the container overlay, not the host.
	//
	// Both unset: dev-on-host behavior (MkdirTemp under /tmp, bind mount
	// the resulting host path into siblings — daemon and airlock share
	// the FS, so it just works).
	//
	// Both set: docker-compose mode. MkdirTemp goes inside the named
	// volume, sibling containers mount the same volume by name. The
	// daemon resolves both ends through the same managed volume so
	// the absolute path airlock writes is the same path the sibling
	// reads.
	AgentCodegenPath   string
	AgentCodegenVolume string

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
		AgentDomain:   resolveAgentDomain(),
		DockerNetwork: os.Getenv("DOCKER_NETWORK"),
		AgentNetwork:  envOr("AGENT_NETWORK", os.Getenv("DOCKER_NETWORK")),

		// Encryption
		EncryptionKey:    requireEnv("ENCRYPTION_KEY"),
		EncryptionKeyOld: os.Getenv("ENCRYPTION_KEY_OLD"),

		// Containers
		ContainerRuntime:      envOr("CONTAINER_RUNTIME", "docker"),
		ContainerImage:        envOr("CONTAINER_IMAGE", "airlock-toolserver"),
		AgentRuntime:          resolveAgentRuntime(),
		AgentMemoryLimitBytes: parseSizeBytes(os.Getenv("AGENT_MEMORY_LIMIT")),

		// Build pipeline
		AgentReposPath:        envOr("AGENT_REPOS_PATH", "/var/lib/airlock/agents"),
		AgentBuilderImage:     envOr("AGENT_BUILDER_IMAGE", DefaultAgentBuilderImage),
		AgentBaseImage:        envOr("AGENT_BASE_IMAGE", DefaultAgentBaseImage),
		AgentRegistryURL:      os.Getenv("AGENT_REGISTRY_URL"),
		BuildkitHost:          os.Getenv("BUILDKIT_HOST"),
		AgentLibsPath:         os.Getenv("AGENT_LIBS_PATH"),
		AgentLibsPathExplicit: os.Getenv("AGENT_LIBS_PATH") != "",
		AgentLibsCacheDir:     envOr("AGENT_LIBS_CACHE_DIR", "/var/lib/airlock/libs"),

		// Codegen workspace — see field doc above. Both empty by default
		// so a `go run ./cmd/airlock` dev invocation keeps using /tmp +
		// bind mounts. docker-compose.yml sets both to enable volume
		// mode.
		AgentCodegenPath:   os.Getenv("AGENT_CODEGEN_PATH"),
		AgentCodegenVolume: os.Getenv("AGENT_CODEGEN_VOLUME"),

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
	c.AgentScheme, c.AgentPort = agentSchemePort(c.PublicURL)
	return c
}

// agentSchemePort returns the scheme + optional explicit port that
// per-agent {slug}.AGENT_DOMAIN URLs should use. Inherited from PublicURL
// so a localhost overlay on `:8443` produces URLs that match what Caddy
// actually serves. Standard 80/443 → empty port (no `:443` cruft in
// production URLs); anything else is preserved verbatim. Falls back to
// ("https", "") when PublicURL is malformed — same effective shape as the
// historic hard-coded "https://" prefix.
func agentSchemePort(publicURL string) (scheme, port string) {
	scheme = "https"
	if u, err := url.Parse(publicURL); err == nil && u.Host != "" {
		scheme = u.Scheme
		p := u.Port()
		if p != "" && !((scheme == "https" && p == "443") || (scheme == "http" && p == "80")) {
			port = p
		}
	}
	return
}

// AgentBaseURL is the external base URL for an agent's registered HTTP
// routes: {scheme}://{slug}.{AgentDomain}[:port], no trailing slash. The
// one place that assembles it — handlers and the container-env builder
// read this, never re-derive scheme/domain/port.
func (c *Config) AgentBaseURL(slug string) string {
	u := c.AgentScheme + "://" + slug + "." + c.AgentDomain
	if c.AgentPort != "" {
		u += ":" + c.AgentPort
	}
	return u
}

// resolveAgentRuntime maps AGENT_SANDBOX to an OCI runtime name. "gvisor"
// (or "runsc") selects gVisor; empty / "runc" / "default" use the Docker
// default runtime. Any other value is passed through verbatim so an
// operator can wire a custom runtime registered in their daemon.
func resolveAgentRuntime() string {
	raw := strings.TrimSpace(os.Getenv("AGENT_SANDBOX"))
	switch strings.ToLower(raw) {
	case "", "runc", "default":
		return ""
	case "gvisor", "runsc":
		return "runsc"
	default:
		return raw
	}
}

// parseSizeBytes parses a human size ("512m", "2g", "1024") into bytes.
// Suffixes k/m/g (and kb/mb/gb) are powers of 1024; a bare number is
// bytes. Empty or unparseable input returns 0, treated as "unlimited".
func parseSizeBytes(s string) int64 {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "gb"), strings.HasSuffix(s, "g"):
		mult, s = 1<<30, strings.TrimRight(s, "gb")
	case strings.HasSuffix(s, "mb"), strings.HasSuffix(s, "m"):
		mult, s = 1<<20, strings.TrimRight(s, "mb")
	case strings.HasSuffix(s, "kb"), strings.HasSuffix(s, "k"):
		mult, s = 1<<10, strings.TrimRight(s, "kb")
	case strings.HasSuffix(s, "b"):
		s = strings.TrimRight(s, "b")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n * mult
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

// resolveAgentDomain returns AGENT_DOMAIN when explicitly set, otherwise
// derives the host portion of PUBLIC_URL. Almost every self-hosted setup
// runs Airlock on the same hostname its agent subdomains hang off
// (`*.airlock.example.com`), so the explicit knob exists only for the
// rare case where they diverge. Port is stripped — AGENT_DOMAIN is a
// bare host.
//
// Panics if neither env var yields a usable host. Subdomain routing is
// load-bearing for every agent (per-agent storage URL, registered
// routes, OAuth callbacks, etc.) so there's no meaningful "no agent
// domain" mode — SubdomainProxy panics at construction in that case
// too. Failing here makes the misconfig surface at startup with the
// obvious error message instead of crashing the router later.
func resolveAgentDomain() string {
	if v := os.Getenv("AGENT_DOMAIN"); v != "" {
		return v
	}
	pu := os.Getenv("PUBLIC_URL")
	if pu == "" {
		panic("config: AGENT_DOMAIN (or PUBLIC_URL to derive it from) is required")
	}
	u, err := url.Parse(pu)
	if err != nil || u.Hostname() == "" {
		panic(fmt.Sprintf("config: PUBLIC_URL %q is not a parseable URL with a hostname; set AGENT_DOMAIN explicitly", pu))
	}
	return u.Hostname()
}
