package api

import (
	"context"
	"net/http"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/execproxy"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/secrets"
	agentssvc "github.com/airlockrun/airlock/service/agents"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	connsvc "github.com/airlockrun/airlock/service/connections"
	convsvc "github.com/airlockrun/airlock/service/conversations"
	execsvc "github.com/airlockrun/airlock/service/execendpoints"
	memberssvc "github.com/airlockrun/airlock/service/members"
	modelssvc "github.com/airlockrun/airlock/service/models"
	runssvc "github.com/airlockrun/airlock/service/runs"
	siblingssvc "github.com/airlockrun/airlock/service/siblings"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"go.uber.org/zap"
)

type RouterConfig struct {
	DB        *db.DB
	JWTSecret string

	// Real-time
	Hub     *realtime.Hub
	PubSub  *realtime.PubSub
	Handler *realtime.Handler

	// Secrets store. Today wraps a local AES-GCM encryptor; the interface
	// is forward-compatible with a Vault-backed implementation.
	Secrets secrets.Store

	// S3 storage
	S3Client *storage.S3Client

	// Build service
	BuildService *builder.BuildService

	// Public URL (for OAuth callbacks, auth URLs)
	PublicURL string

	// OAuth client
	OAuthClient *oauth.Client

	// Telegram driver (for bridge validation via getMe)
	TelegramDriver *trigger.TelegramDriver

	// Discord driver (for bridge validation via /users/@me)
	DiscordDriver *trigger.DiscordDriver

	// Trigger system
	Dispatcher    *trigger.Dispatcher
	Scheduler     *trigger.Scheduler
	BridgeManager *trigger.BridgeManager

	// Container manager
	Containers container.ContainerManager

	// Prompt proxy (for web conversations)
	PromptProxy *trigger.PromptProxy

	// Agent subdomain routing (e.g. "airlock.host" → {slug}.airlock.host)
	AgentDomain string

	// AgentBaseURL builds an agent's external route base
	// ({scheme}://{slug}.{domain}[:port]). Sourced from config.Config —
	// the single place that derives it; handlers never re-derive.
	AgentBaseURL func(slug string) string

	// LLM debugging proxy (e.g. telescope -watch)
	LLMProxyURL string

	// Dev escape hatch: force base64 attachment delivery regardless of
	// provider URL capability. Useful when the public URL isn't reachable
	// from the model provider (e.g. localhost without a tunnel).
	ForceInlineAttachments bool

	// Path to the on-disk activation code file — cleared after Activate
	// succeeds so the one-time secret doesn't linger on disk.
	ActivationCodeFile string

	// Reverse proxy real IP extraction
	RealIP *RealIPConfig

	// Logger
	Logger *zap.Logger
}

func NewRouter(cfg RouterConfig) http.Handler {
	if cfg.Secrets == nil {
		panic("api: RouterConfig.Encryptor is required")
	}
	if cfg.Hub == nil {
		panic("api: RouterConfig.Hub is required")
	}
	if cfg.Handler == nil {
		panic("api: RouterConfig.Handler is required")
	}

	r := chi.NewRouter()

	// Cross-cutting middleware (RequestID, RealIP, requestLogger, recoverers)
	// is applied on the outer wrapper below, so it covers both the chi-routed
	// platform API and the SubdomainProxy-intercepted agent traffic.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// SSH dialer for RegisterExecEndpoint. Owns a per-process *ssh.Client
	// cache + background reaper; lives for the lifetime of the server.
	// Shared by the agent-internal /api/agent/exec handler and the
	// operator-facing /api/v1/agents/{id}/exec-endpoints handlers.
	execDialer := execproxy.NewSSHDialer(
		cfg.Secrets,
		newTOFUPinner(cfg.DB.Pool()),
		cfg.Logger,
	)

	authHandler := NewAuthHandler(cfg.DB, cfg.JWTSecret, cfg.ActivationCodeFile, cfg.Logger.Named("auth"))
	providersHandler := NewProvidersHandler(cfg.DB, cfg.Secrets)
	gitCredsHandler := NewGitCredentialsHandler(cfg.DB, cfg.Secrets)
	gitWebhookHandler := NewGitWebhookHandler(cfg.DB, cfg.BuildService, cfg.Logger.Named("git-webhook"))
	usersHandler := NewUsersHandler(cfg.DB)
	sysSettingsHandler := &settingsHandler{db: cfg.DB, encryptor: cfg.Secrets, logger: cfg.Logger.Named("settings")}

	// Health check (public, no auth — reverse proxies and orchestrators need
	// to hit this without credentials). 200 if DB+S3 reachable, 503 otherwise.
	healthH := newHealthHandler(cfg.DB, cfg.S3Client, cfg.Logger.Named("health"))
	r.Get("/health", healthH.Check)

	// WebSocket endpoint (public, auth via query param)
	wsHandler := NewWSHandler(cfg.DB, cfg.Hub, cfg.Handler, cfg.JWTSecret, cfg.Logger.Named("ws"))
	r.Get("/ws", wsHandler.Upgrade)

	relayH := &relayHandler{
		jwtSecret:   cfg.JWTSecret,
		agentDomain: cfg.AgentDomain,
		publicURL:   cfg.PublicURL,
		logger:      cfg.Logger.Named("relay"),
	}

	// Public auth routes
	r.Route("/auth", func(r chi.Router) {
		r.Get("/status", authHandler.Status)
		r.Post("/activate", authHandler.Activate)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", authHandler.Refresh)

		// Authenticated: change password, relay code
		r.Group(func(r chi.Router) {
			r.Use(auth.Middleware(cfg.JWTSecret))
			r.Post("/change-password", authHandler.ChangePassword)
			r.Post("/relay-code", relayH.GenerateCode)
		})
	})

	// Credential, bridge, and identity handlers. The connections service
	// takes function-typed deps for MCP discovery + auth injection so it
	// doesn't have to depend on the goai/mcp client directly.
	credSvcDiscovery := func(ctx context.Context, serverURL string, authInjection []byte, creds string) ([]connsvc.ToolInfo, string, error) {
		tools, instructions, err := discoverMCPTools(ctx, serverURL, authInjection, creds)
		if err != nil {
			return nil, "", err
		}
		out := make([]connsvc.ToolInfo, len(tools))
		for i, t := range tools {
			out[i] = connsvc.ToolInfo{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema}
		}
		return out, instructions, nil
	}
	credH := newCredentialHandler(connsvc.New(
		cfg.DB,
		cfg.Secrets,
		cfg.OAuthClient,
		cfg.PublicURL,
		cfg.Dispatcher.RefreshAgent,
		cfg.Logger.Named("credentials"),
		credSvcDiscovery,
		discoverMCPAuth,
		injectAuth,
		mcpHTTPClient,
	))
	brH := newBridgeHandler(bridgessvc.New(
		cfg.DB, cfg.Secrets, cfg.TelegramDriver, cfg.DiscordDriver,
		cfg.BridgeManager, cfg.Logger.Named("bridges"),
	))
	idH := &identityHandler{
		db:         cfg.DB,
		encryptor:  cfg.Secrets,
		telegram:   cfg.TelegramDriver,
		discord:    cfg.DiscordDriver,
		hmacSecret: cfg.JWTSecret, // reuse JWT secret for HMAC
		publicURL:  cfg.PublicURL,
		logger:     cfg.Logger.Named("identity"),
	}

	// Public endpoints (no JWT required)
	r.Get("/api/v1/credentials/oauth/callback", credH.OAuthCallback)
	r.Get("/api/v1/catalog/providers", providersHandler.ListCatalogProviders)
	r.Get("/auth-external", idH.AuthExternal)

	// OAuth Authorization Server handler — built once and reused by
	// both the top-level unauthenticated routes (/.well-known, /oauth/*)
	// and the /api/v1/oauth/* routes that require a user JWT.
	oauthH := newOAuthServerHandler(cfg.DB, cfg.JWTSecret, cfg.PublicURL, cfg.Logger.Named("oauth"))

	// Authenticated API routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(auth.Middleware(cfg.JWTSecret))
		r.Use(identityLogger)

		r.Get("/me", authHandler.Me)

		// Per-user git credentials (PATs for accessing external git
		// remotes attached to agents). Self-service: any authenticated
		// user can manage their own credentials; not admin-gated.
		r.Route("/me/git/credentials", func(r chi.Router) {
			r.Get("/", gitCredsHandler.List)
			r.Post("/", gitCredsHandler.Create)
			r.Delete("/{id}", gitCredsHandler.Delete)
		})

		// OAuth consent + grant management. The SPA hits /oauth/consent
		// (POST) to approve or deny a pending /oauth/authorize request;
		// /api/v1/oauth/grants lists and revokes existing consents.
		r.Post("/oauth/consent", oauthH.Consent)
		r.Get("/oauth/grants", oauthH.ListGrants)
		r.Delete("/oauth/grants/{clientID}/{agentID}", oauthH.RevokeGrant)

		// Slim tenant directory for member-picker dropdowns. Any authenticated
		// user — agent admins who aren't tenant admins still need this list.
		r.Get("/users/selectable", usersHandler.ListSelectable)

		// User management (admin only)
		r.Route("/users", func(r chi.Router) {
			r.Use(auth.RequireTenantRole("admin"))
			r.Get("/", usersHandler.List)
			r.Post("/", usersHandler.Create)
			r.Patch("/{userID}", usersHandler.UpdateRole)
			r.Delete("/{userID}", usersHandler.Delete)
		})

		// System settings. GET is readable by any authenticated user so the
		// Agent Create flow can prefill system defaults; PUT stays admin-only.
		r.Get("/settings", sysSettingsHandler.Get)
		r.With(auth.RequireTenantRole("admin")).Put("/settings", sysSettingsHandler.Update)

		// Provider management (admin/owner only)
		r.Route("/providers", func(r chi.Router) {
			r.Use(auth.RequireTenantRole("admin"))
			r.Get("/", providersHandler.List)
			r.Post("/", providersHandler.Create)
			r.Route("/{id}", func(r chi.Router) {
				r.Patch("/", providersHandler.Update)
				r.Delete("/", providersHandler.Delete)
			})
		})

		// Catalog (read-only, any authenticated user)
		r.Get("/catalog/providers", providersHandler.ListCatalogProviders)
		r.Get("/catalog/models", providersHandler.ListCatalogModels)
		capH := &capabilitiesHandler{db: cfg.DB, logger: cfg.Logger.Named("capabilities")}
		r.Get("/catalog/capabilities", capH.ListCapabilities)

		// Credential management
		r.Post("/credentials/oauth/start", credH.OAuthStart)
		r.Post("/credentials/mcp/oauth/start", credH.MCPOAuthStart)

		// Agent management (Phase 6)
		agH := newAgentsHandler(
			agentssvc.New(
				cfg.DB, cfg.BuildService, cfg.Dispatcher,
				cfg.Containers, cfg.BridgeManager,
				cfg.Logger.Named("agents"),
			),
			memberssvc.New(cfg.DB, cfg.Logger.Named("members")),
			cfg.PublicURL,
			cfg.AgentBaseURL,
		)
		rH := newRunsHandler(
			runssvc.New(cfg.DB, cfg.Dispatcher, cfg.Logger.Named("runs")),
			cfg.S3Client,
			cfg.Logger.Named("runs"),
		)
		cH := &conversationsHandler{
			svc: convsvc.New(cfg.DB, cfg.S3Client, cfg.Logger.Named("conversations"),
				func(parts []byte, agentID string) []string {
					return ExtractCanonicalKeys(parts, agentID)
				}),
			db:          cfg.DB,
			dispatcher:  cfg.Dispatcher,
			promptProxy: cfg.PromptProxy,
			bridgeMgr:   cfg.BridgeManager,
			pubsub:      cfg.PubSub,
			s3:          cfg.S3Client,
			convLocks:   newConvMutexMap(),
			logger:      cfg.Logger.Named("conversations"),
		}
		mH := newModelsHandler(modelssvc.New(cfg.DB, cfg.Logger.Named("models")))
		siblingsH := newSiblingsHandler(siblingssvc.New(cfg.DB, cfg.Dispatcher, cfg.Logger.Named("siblings")))

		// Wire post-upgrade notifications to conversations handler.
		cfg.BuildService.SetUpgradeNotifier(cH)

		r.Route("/agents", func(r chi.Router) {
			r.Get("/", agH.List)
			r.Post("/", agH.Create)

			r.Route("/{agentID}", func(r chi.Router) {
				r.Get("/", agH.Get)
				r.Patch("/", agH.Update)
				r.Delete("/", agH.Delete)
				r.Post("/stop", agH.Stop)
				r.Post("/start", agH.Start)
				r.Post("/suspend", agH.Suspend)
				r.Post("/upgrade", agH.Upgrade)
				r.Post("/rollback", agH.Rollback)
				r.Post("/prompt", cH.Prompt)
				r.Post("/files", cH.UploadFile)

				// Model configuration (per-agent capability overrides + slots)
				r.Get("/models", mH.GetConfig)
				r.Put("/models", mH.UpdateConfig)

				// Conversations
				r.Get("/conversations", cH.ListConversations)
				r.Post("/conversations", cH.CreateConversation)

				// Builds
				r.Get("/builds", agH.ListBuilds)
				r.Get("/builds/{buildID}", agH.GetBuild)
				r.Post("/builds/cancel", agH.CancelBuild)

				// External git remote (optional, per agent)
				r.Get("/git", agH.GetGitConfig)
				r.Post("/git/connect", agH.ConnectGit)
				r.Post("/git/disconnect", agH.DisconnectGit)

				// Runs
				r.Get("/runs", rH.ListRuns)

				// Webhooks, Crons & Functions
				r.Get("/webhooks", agH.ListWebhooks)
				r.Get("/crons", agH.ListCrons)
				r.Post("/crons/{name}/fire", agH.FireCron)
				r.Get("/tools", agH.ListTools)

				// Members
				r.Get("/members", agH.ListMembers)
				r.Post("/members", agH.AddMember)
				r.Delete("/members/{userID}", agH.RemoveMember)

				// A2A: sibling address book + MCP access toggles. All
				// admin-gated (siblingsH.requireParentAdmin); user JWT is
				// already in ctx via the /api/v1 group middleware.
				r.Get("/siblings", siblingsH.List)
				r.Get("/siblings/addable", siblingsH.ListAddable)
				r.Post("/siblings", siblingsH.Add)
				r.Delete("/siblings/{siblingID}", siblingsH.Remove)
				r.Get("/a2a-settings", siblingsH.GetA2ASettings)
				r.Put("/a2a-settings", siblingsH.UpdateA2ASettings)

				// Credentials & Connections
				r.Get("/connections", credH.ListConnections)
				r.Route("/credentials/{slug}", func(r chi.Router) {
					r.Get("/", credH.CredentialStatus)
					r.Post("/", credH.SetAPIKey)
					r.Delete("/", credH.RevokeCredential)
					r.Post("/test", credH.TestCredential)
					r.Put("/oauth-app", credH.SetOAuthApp)
				})

				// Exec endpoints (operator-configured SSH targets the agent's
				// RegisterExecEndpoint declares).
				execEpH := newExecEndpointsHandler(execsvc.New(cfg.DB.Pool(), cfg.Secrets, execDialer, cfg.Logger))
				r.Get("/exec-endpoints", execEpH.List)
				r.Route("/exec-endpoints/{slug}", func(r chi.Router) {
					r.Put("/", execEpH.Configure)
					r.Post("/rotate-keypair", execEpH.RotateKeypair)
					r.Post("/unpin-host-key", execEpH.UnpinHostKey)
					r.Post("/test", execEpH.Test)
				})

				// MCP Servers
				r.Get("/mcp-servers", credH.ListMCPServers)
				r.Route("/mcp-servers/{slug}/credentials", func(r chi.Router) {
					r.Get("/", credH.MCPCredentialStatus)
					r.Post("/", credH.SetMCPToken)
					r.Delete("/", credH.RevokeMCPCredential)
					r.Post("/test", credH.TestMCPCredential)
					r.Put("/oauth-app", credH.SetMCPOAuthApp)
					r.Delete("/oauth-app", credH.RevokeMCPOAuthApp)
				})

				// Env vars (operator UI). Slot itself is created by the
				// agent's syncWithAirlock — operators only set/clear values.
				r.Get("/env-vars", credH.ListEnvVars)
				r.Post("/env-vars/{slug}", credH.SetEnvVarValue)
				r.Delete("/env-vars/{slug}", credH.ClearEnvVarValue)

				// Aggregate setup-completeness signal for the agent
				// detail header — surfaces unconfigured slots across
				// connections, MCP servers, and env vars.
				r.Get("/setup-status", credH.SetupStatus)
			})
		})

		// Top-level conversation and run routes (not nested under agent).
		// Topic subscription is conversation-scoped: the conversation that
		// subscribes is the one that receives the topic's notifications.
		r.Get("/conversations", cH.ListAllConversations)
		r.Get("/conversations/{convID}", cH.GetConversation)
		r.Get("/conversations/{convID}/messages", cH.ListConversationMessages)
		r.Delete("/conversations/{convID}", cH.DeleteConversation)
		r.Get("/conversations/{convID}/topics", cH.ListTopics)
		r.Post("/conversations/{convID}/topics/{slug}/subscribe", cH.SubscribeTopic)
		r.Delete("/conversations/{convID}/topics/{slug}/subscribe", cH.UnsubscribeTopic)
		r.Get("/runs/{runID}", rH.GetRun)
		r.Get("/runs/{runID}/logs", rH.GetRunLogs)
		r.Delete("/runs/{runID}", rH.CancelRun)

		// Bridge management
		r.Route("/bridges", func(r chi.Router) {
			r.Get("/", brH.ListBridges)
			r.Post("/", brH.CreateBridge)
			r.Put("/{bridgeID}", brH.UpdateBridge)
			r.Delete("/{bridgeID}", brH.DeleteBridge)
		})

		// Platform identity management
		r.Get("/link-identity/preview", idH.LinkIdentityPreview)
		r.Post("/link-identity", idH.LinkIdentity)
		r.Route("/identities", func(r chi.Router) {
			r.Get("/", idH.ListIdentities)
			r.Delete("/{identityID}", idH.UnlinkIdentity)
		})
	})

	// Caddy on-demand TLS validation (no auth — called by Caddy internally)
	if cfg.AgentDomain != "" {
		caddyH := &CaddyAskHandler{
			db:          cfg.DB,
			agentDomain: cfg.AgentDomain,
			logger:      cfg.Logger.Named("caddy"),
		}
		r.Get("/caddy/ask", caddyH.Ask)
	}

	// Public webhook ingress (no auth — verification is per-webhook via hmac/token)
	if cfg.Dispatcher != nil {
		wh := &webhookIngressHandler{
			dispatcher: cfg.Dispatcher,
			db:         cfg.DB,
			encryptor:  cfg.Secrets,
			logger:     cfg.Logger.Named("webhook-ingress"),
		}
		r.Post("/webhooks/{agentID}/{path}", wh.HandleWebhook)
		// External git push notifications (GitHub, GitLab). Signature
		// verification gated by the per-agent git_webhook_secret.
		r.Post("/webhooks/git/{agentID}", gitWebhookHandler.Handle)
	}

	// (channel event endpoint removed — bridges use long-polling, not push)

	// Agent API routes (authenticated via agent JWT)
	ah := &agentHandler{
		db:                     cfg.DB,
		encryptor:              cfg.Secrets,
		s3:                     cfg.S3Client,
		builder:                cfg.BuildService,
		pubsub:                 cfg.PubSub,
		bridgeMgr:              cfg.BridgeManager,
		scheduler:              cfg.Scheduler,
		publicURL:              cfg.PublicURL,
		agentBaseURL:           cfg.AgentBaseURL,
		llmProxyURL:            cfg.LLMProxyURL,
		forceInlineAttachments: cfg.ForceInlineAttachments,
		jwtSecret:              cfg.JWTSecret,
		dispatcher:             cfg.Dispatcher,
		execDialer:             execDialer,
		logger:                 cfg.Logger.Named("agent-api"),
	}
	// Silence "unused" if dbq import only used by helper newTOFUPinner.
	_ = dbq.New

	// MCP server endpoint — A2A entry point + external MCP client
	// entry point. Mounted at top level (outside the /api/agent
	// agent-JWT route group) because its auth model is multi-principal
	// (user JWT / agent JWT / OAuth-issued access token). The
	// /public-mcp route serves the same JSON-RPC interface anonymously,
	// gated by `agent.allow_public_mcp`.
	mcp := NewMCPServer(cfg.Dispatcher, cfg.PubSub, cfg.Logger.Named("mcp"))
	r.Post("/api/agent/{identifier}/mcp", func(w http.ResponseWriter, req *http.Request) {
		mcp.ServeHTTP(w, req, ah)
	})
	r.Post("/api/agent/{identifier}/public-mcp", func(w http.ResponseWriter, req *http.Request) {
		mcp.ServePublicHTTP(w, req, ah)
	})

	// Server-side OAuth 2.1 — Authorization Server endpoints used by
	// external MCP clients (Claude Desktop, VSCode, Codex CLI) to
	// self-register, obtain audience-bound access tokens, and rotate
	// refresh tokens against airlock's MCP endpoints. The /.well-known
	// discovery docs are unauthenticated. oauthH is built earlier (before
	// /api/v1) so both route groups share one instance.
	r.Get("/.well-known/oauth-authorization-server", oauthH.ASMetadata)
	r.Get("/.well-known/oauth-protected-resource/api/agent/{identifier}/mcp", oauthH.ResourceMetadata)
	r.Post("/oauth/register", oauthH.Register)
	r.Get("/oauth/authorize", oauthH.Authorize)
	r.Post("/oauth/token", oauthH.Token)

	r.Route("/api/agent", func(r chi.Router) {
		r.Use(auth.AgentMiddleware(cfg.JWTSecret))
		r.Put("/connections/{slug}", ah.UpsertConnection)
		r.Put("/exec-endpoints/{slug}", ah.UpsertExecEndpoint)
		r.Post("/exec/{slug}", ah.AgentExec)
		r.Put("/sync", ah.Sync)
		r.Post("/llm/stream", ah.LLMStream)
		r.Post("/llm/image", ah.ImageGenerate)
		r.Post("/llm/embedding", ah.Embed)
		r.Post("/llm/speech", ah.SpeechGenerate)
		r.Post("/llm/transcription", ah.Transcribe)
		r.Post("/proxy/{slug}", ah.ServiceProxy)
		r.Post("/search", ah.Search)
		r.Post("/webfetch", ah.WebFetch)
		r.Post("/http", ah.AgentHTTP)
		r.Post("/storage/copy", ah.StorageCopy)
		r.Post("/storage/info", ah.StorageInfo)
		r.Post("/storage/share", ah.StorageShare)
		r.Put("/storage/*", ah.StorageStore)
		r.Get("/storage/*", ah.StorageLoad)
		r.Delete("/storage/*", ah.StorageDelete)
		r.Get("/storage", ah.StorageList)
		r.Get("/session/{convID}/messages", ah.SessionLoad)
		r.Post("/session/{convID}/messages", ah.SessionAppend)
		r.Post("/session/{convID}/compact", ah.SessionCompact)
		r.Post("/run/create", ah.CreateRun)
		r.Post("/run/complete", ah.RunComplete)
		r.Get("/run/{runID}/checkpoint", ah.GetCheckpoint)
		r.Post("/upgrade", ah.Upgrade)
		r.Post("/print", ah.Print)
		r.Post("/topic/{slug}/subscribe", ah.TopicSubscribe)
		r.Delete("/topic/{slug}/subscribe", ah.TopicUnsubscribe)
		r.Put("/mcp-servers/{slug}", ah.UpsertMCPServer)
		r.Post("/mcp/{slug}/tools/call", ah.MCPToolCall)
		r.Put("/env-vars/{slug}", ah.UpsertEnvVar)
		r.Get("/env-vars/{slug}", ah.GetEnvVarValue)
	})

	// Cross-cutting middleware wraps the entire handler tree (chi router and,
	// when configured, the SubdomainProxy) so agent subdomain traffic gets the
	// same request_id / real client IP / access log as the platform API.
	//
	// Order, outermost first:
	//   chimw.Recoverer   last-resort net for panics in middleware below
	//   chimw.RequestID   generates the per-request ID requestLogger reads
	//   RealIP            normalizes r.RemoteAddr from trusted-proxy headers
	//   requestLogger     stores the per-request zap logger in ctx; access log
	//   zapRecoverer      catches handler panics with full request context
	var handler http.Handler = r
	if cfg.AgentDomain != "" {
		handler = SubdomainProxy(cfg.AgentDomain, cfg.DB, cfg.S3Client, cfg.Dispatcher, cfg.JWTSecret, cfg.PublicURL, r)
	}
	handler = zapRecoverer(handler)
	handler = requestLogger(cfg.Logger)(handler)
	handler = RealIP(cfg.RealIP)(handler)
	handler = chimw.RequestID(handler)
	handler = chimw.Recoverer(handler)
	return handler
}
