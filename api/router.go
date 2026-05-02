package api

import (
	"net/http"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"go.uber.org/zap"
)

// OIDCRoutes is the interface for OIDC authentication endpoints.
type OIDCRoutes interface {
	Authorize(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request)
}

type RouterConfig struct {
	DB        *db.DB
	JWTSecret string
	OIDC      OIDCRoutes // nil if OIDC not configured

	// Real-time
	Hub     *realtime.Hub
	PubSub  *realtime.PubSub
	Handler *realtime.Handler

	// Encryption (for provider API keys)
	Encryptor *crypto.Encryptor

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
	if cfg.Encryptor == nil {
		panic("api: RouterConfig.Encryptor is required")
	}
	if cfg.Hub == nil {
		panic("api: RouterConfig.Hub is required")
	}
	if cfg.Handler == nil {
		panic("api: RouterConfig.Handler is required")
	}

	r := chi.NewRouter()

	// Standard middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(RealIP(cfg.RealIP))
	r.Use(requestLogger(cfg.Logger))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	authHandler := NewAuthHandler(cfg.DB, cfg.JWTSecret, cfg.ActivationCodeFile, cfg.Logger.Named("auth"))
	providersHandler := NewProvidersHandler(cfg.DB, cfg.Encryptor)
	usersHandler := NewUsersHandler(cfg.DB)
	sysSettingsHandler := &settingsHandler{db: cfg.DB, encryptor: cfg.Encryptor, logger: cfg.Logger.Named("settings")}

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

		if cfg.OIDC != nil {
			r.Get("/oidc/authorize", cfg.OIDC.Authorize)
			r.Get("/oidc/callback", cfg.OIDC.Callback)
		} else {
			// Return 404 when OIDC not configured
			r.Get("/oidc/*", func(w http.ResponseWriter, r *http.Request) {
				writeError(w, http.StatusNotFound, "OIDC not configured")
			})
		}
	})

	// Credential, bridge, and identity handlers
	credH := &credentialHandler{
		db:          cfg.DB,
		encryptor:   cfg.Encryptor,
		oauthClient: cfg.OAuthClient,
		publicURL:   cfg.PublicURL,
		logger:      cfg.Logger.Named("credentials"),
		dispatcher:  cfg.Dispatcher,
	}
	brH := &bridgeHandler{
		db:        cfg.DB,
		encryptor: cfg.Encryptor,
		telegram:  cfg.TelegramDriver,
		bridgeMgr: cfg.BridgeManager,
		logger:    cfg.Logger.Named("bridges"),
	}
	idH := &identityHandler{
		db:         cfg.DB,
		encryptor:  cfg.Encryptor,
		telegram:   cfg.TelegramDriver,
		hmacSecret: cfg.JWTSecret, // reuse JWT secret for HMAC
		publicURL:  cfg.PublicURL,
		logger:     cfg.Logger.Named("identity"),
	}

	// Public endpoints (no JWT required)
	r.Get("/api/v1/credentials/oauth/callback", credH.OAuthCallback)
	r.Get("/api/v1/catalog/providers", providersHandler.ListCatalogProviders)
	r.Get("/auth-external", idH.AuthExternal)

	// Authenticated API routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(auth.Middleware(cfg.JWTSecret))
		r.Use(identityLogger)

		r.Get("/me", authHandler.Me)

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
		agH := &agentsHandler{
			db:          cfg.DB,
			builder:     cfg.BuildService,
			dispatcher:  cfg.Dispatcher,
			encryptor:   cfg.Encryptor,
			containers:  cfg.Containers,
			promptProxy: cfg.PromptProxy,
			bridgeMgr:   cfg.BridgeManager,
			publicURL:   cfg.PublicURL,
			logger:      cfg.Logger.Named("agents"),
		}
		rH := &runsHandler{
			db:         cfg.DB,
			dispatcher: cfg.Dispatcher,
			s3:         cfg.S3Client,
			logger:     cfg.Logger.Named("runs"),
		}
		cH := &conversationsHandler{
			db:          cfg.DB,
			dispatcher:  cfg.Dispatcher,
			promptProxy: cfg.PromptProxy,
			bridgeMgr:   cfg.BridgeManager,
			pubsub:      cfg.PubSub,
			s3:          cfg.S3Client,
			convLocks:   newConvMutexMap(),
			logger:      cfg.Logger.Named("conversations"),
		}
		mH := &modelsHandler{
			db:     cfg.DB,
			logger: cfg.Logger.Named("models"),
			agents: agH,
		}

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
				r.Post("/upgrade", agH.Upgrade)
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

				// Credentials & Connections
				r.Get("/connections", credH.ListConnections)
				r.Route("/credentials/{slug}", func(r chi.Router) {
					r.Get("/", credH.CredentialStatus)
					r.Post("/", credH.SetAPIKey)
					r.Delete("/", credH.RevokeCredential)
					r.Post("/test", credH.TestCredential)
					r.Put("/oauth-app", credH.SetOAuthApp)
				})

				// Topics
				r.Get("/topics", cH.ListTopics)
				r.Post("/topics/{slug}/subscribe", cH.SubscribeTopic)
				r.Delete("/topics/{slug}/subscribe", cH.UnsubscribeTopic)

				// MCP Servers
				r.Get("/mcp-servers", credH.ListMCPServers)
				r.Route("/mcp-servers/{slug}/credentials", func(r chi.Router) {
					r.Get("/", credH.MCPCredentialStatus)
					r.Post("/", credH.SetMCPToken)
					r.Delete("/", credH.RevokeMCPCredential)
					r.Put("/oauth-app", credH.SetMCPOAuthApp)
				})
			})
		})

		// Top-level conversation and run routes (not nested under agent)
		r.Get("/conversations/{convID}", cH.GetConversation)
		r.Get("/conversations/{convID}/messages", cH.ListConversationMessages)
		r.Delete("/conversations/{convID}", cH.DeleteConversation)
		r.Get("/runs/{runID}", rH.GetRun)
		r.Get("/runs/{runID}/logs", rH.GetRunLogs)
		r.Delete("/runs/{runID}", rH.CancelRun)
		r.Post("/runs/{runID}/extend", rH.ExtendRun)

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
			encryptor:  cfg.Encryptor,
			logger:     cfg.Logger.Named("webhook-ingress"),
		}
		r.Post("/webhooks/{agentID}/{path}", wh.HandleWebhook)
	}

	// (channel event endpoint removed — bridges use long-polling, not push)

	// Agent API routes (authenticated via agent JWT)
	ah := &agentHandler{
		db:                     cfg.DB,
		encryptor:              cfg.Encryptor,
		s3:                     cfg.S3Client,
		builder:                cfg.BuildService,
		pubsub:                 cfg.PubSub,
		bridgeMgr:              cfg.BridgeManager,
		scheduler:              cfg.Scheduler,
		publicURL:              cfg.PublicURL,
		agentDomain:            cfg.AgentDomain,
		llmProxyURL:            cfg.LLMProxyURL,
		forceInlineAttachments: cfg.ForceInlineAttachments,
		logger:                 cfg.Logger.Named("agent-api"),
	}
	r.Route("/api/agent", func(r chi.Router) {
		r.Use(auth.AgentMiddleware(cfg.JWTSecret))
		r.Put("/connections/{slug}", ah.UpsertConnection)
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
	})

	// Wrap with subdomain proxy for agent custom routes.
	if cfg.AgentDomain != "" {
		return SubdomainProxy(cfg.AgentDomain, cfg.DB, cfg.S3Client, cfg.Dispatcher, cfg.JWTSecret, cfg.PublicURL, cfg.Logger.Named("proxy"), r)
	}

	return r
}
