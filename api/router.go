package api

import (
	"context"
	"net/http"
	"time"

	"github.com/airlockrun/airlock/agentapi"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/auth/passkey"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/hostapi"
	"github.com/airlockrun/airlock/networkpolicy"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/secrets"
	agentssvc "github.com/airlockrun/airlock/service/agents"
	agentstoragesvc "github.com/airlockrun/airlock/service/agentstorage"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	catalogsvc "github.com/airlockrun/airlock/service/catalog"
	connsvc "github.com/airlockrun/airlock/service/connections"
	connectorartifactssvc "github.com/airlockrun/airlock/service/connectorartifacts"
	connectordirectoriessvc "github.com/airlockrun/airlock/service/connectordirectories"
	connectorjobssvc "github.com/airlockrun/airlock/service/connectorjobs"
	connectororchestrationsvc "github.com/airlockrun/airlock/service/connectororchestration"
	connectorssvc "github.com/airlockrun/airlock/service/connectors"
	convsvc "github.com/airlockrun/airlock/service/conversations"
	gitcredssvc "github.com/airlockrun/airlock/service/gitcredentials"
	grantssvc "github.com/airlockrun/airlock/service/grants"
	hostssvc "github.com/airlockrun/airlock/service/hosts"
	identitysvc "github.com/airlockrun/airlock/service/identity"
	integrationssvc "github.com/airlockrun/airlock/service/integrations"
	jobssvc "github.com/airlockrun/airlock/service/jobs"
	managedbotssvc "github.com/airlockrun/airlock/service/managedbots"
	memberssvc "github.com/airlockrun/airlock/service/members"
	modelssvc "github.com/airlockrun/airlock/service/models"
	needssvc "github.com/airlockrun/airlock/service/needs"
	passkeyssvc "github.com/airlockrun/airlock/service/passkeys"
	providerssvc "github.com/airlockrun/airlock/service/providers"
	resourcessvc "github.com/airlockrun/airlock/service/resources"
	runssvc "github.com/airlockrun/airlock/service/runs"
	settingssvc "github.com/airlockrun/airlock/service/settings"
	siblingssvc "github.com/airlockrun/airlock/service/siblings"
	usagesvc "github.com/airlockrun/airlock/service/usage"
	userssvc "github.com/airlockrun/airlock/service/users"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/sysagent"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
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
	S3Client                *storage.S3Client
	ConnectorStorageOrigins []string

	// Build service
	BuildService *builder.BuildService

	// Public URL (for OAuth callbacks, auth URLs)
	PublicURL string

	// OAuth client
	OAuthClient *oauth.Client

	// Telegram driver (for bridge validation via getMe)
	TelegramDriver *trigger.TelegramDriver

	// Trigger system
	Dispatcher         *trigger.Dispatcher
	Scheduler          *trigger.Scheduler
	BridgeManager      *trigger.BridgeManager
	Jobs               *jobssvc.Service
	ConnectorArtifacts *connectorartifactssvc.Service

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
	// Non-public CIDRs available to Airlock-brokered agent HTTP calls.
	HTTPNetwork *networkpolicy.Policy
	// HTTP client for configured model-provider endpoints.
	ProviderEndpointHTTPClient *http.Client

	// Path to the on-disk activation code file — cleared after Activate
	// succeeds so the one-time secret doesn't linger on disk.
	ActivationCodeFile string

	// Reverse proxy real IP extraction
	RealIP *RealIPConfig

	// Logger
	Logger *zap.Logger
}

func NewRouter(cfg RouterConfig) http.Handler {
	if cfg.HTTPNetwork == nil {
		panic("api: HTTP network policy is required")
	}
	if cfg.ProviderEndpointHTTPClient == nil {
		panic("api: provider endpoint HTTP client is required")
	}
	if cfg.Secrets == nil {
		panic("api: RouterConfig.Encryptor is required")
	}
	if cfg.Hub == nil {
		panic("api: RouterConfig.Hub is required")
	}
	if cfg.Handler == nil {
		panic("api: RouterConfig.Handler is required")
	}
	if cfg.Jobs == nil {
		panic("api: RouterConfig.Jobs is required")
	}
	if cfg.ConnectorArtifacts == nil {
		panic("api: RouterConfig.ConnectorArtifacts is required")
	}

	r := chi.NewRouter()

	// Cross-cutting middleware (RequestID, RealIP, requestLogger, recoverers)
	// is applied on the outer wrapper below, so it covers both the chi-routed
	// platform API and the SubdomainProxy-intercepted agent traffic.
	r.Use(cors.Handler(platformCORSOptions(cfg.PublicURL)))

	authHandler := NewAuthHandler(cfg.DB, cfg.JWTSecret, cfg.ActivationCodeFile, cfg.PublicURL, cfg.Logger.Named("auth"))
	webAuthn, err := passkey.New(cfg.PublicURL)
	if err != nil {
		panic("api: build webauthn from PUBLIC_URL: " + err.Error())
	}
	passkeyHandler := NewPasskeyHandler(passkeyssvc.New(cfg.DB, webAuthn, cfg.Logger.Named("passkeys")), cfg.DB, cfg.JWTSecret, cfg.PublicURL)
	deviceLoginH := newDeviceLoginHandler(cfg.DB, cfg.JWTSecret, cfg.PublicURL)
	providersHandler := NewProvidersHandler(providerssvc.New(cfg.DB, cfg.Secrets, cfg.ProviderEndpointHTTPClient, cfg.Logger.Named("providers")))
	gitCredsHandler := NewGitCredentialsHandler(gitcredssvc.New(cfg.DB, cfg.Secrets, cfg.Logger.Named("gitcredentials")))
	gitWebhookHandler := NewGitWebhookHandler(cfg.DB, cfg.BuildService, cfg.Secrets, cfg.Logger.Named("git-webhook"))
	usersHandler := NewUsersHandler(cfg.DB, userssvc.New(cfg.DB, cfg.BridgeManager, cfg.Logger.Named("users")))
	grantsHandler := NewGrantsHandler(grantssvc.New(cfg.DB, cfg.Logger.Named("grants")))
	needsHandler := NewNeedsHandler(needssvc.NewService(cfg.DB, cfg.Dispatcher.RefreshAgent, cfg.Logger.Named("needs")))
	connectorsService := connectorssvc.New(cfg.DB, cfg.Logger.Named("connectors"))
	resourcesHandler := NewResourcesHandler(resourcessvc.New(cfg.DB, connectorsService, cfg.Logger.Named("resources")))
	connectorJobsService := connectorjobssvc.New(cfg.DB, cfg.Logger.Named("connector-jobs"))
	connectorOrchestrationService := connectororchestrationsvc.New(cfg.DB, cfg.Logger.Named("connector-orchestration"))
	hostsService := hostssvc.New(cfg.DB, cfg.PublicURL, cfg.ConnectorStorageOrigins, cfg.S3Client, connectorJobsService, cfg.Secrets, cfg.Logger.Named("hosts"))
	hostsHandler := newHostsHandler(hostsService)
	hostProtocol := hostapi.New(hostsService, connectorOrchestrationService, cfg.Logger.Named("host-api"))
	fileService := agentstoragesvc.New(cfg.DB)
	connectorDirectoriesService := connectordirectoriessvc.New(cfg.DB, connectorJobsService, fileService, cfg.S3Client)
	connectorsHandler := newConnectorsHandler(connectorsService, connectorOrchestrationService)
	connectorArtifactsHandler := newConnectorArtifactsHandler(cfg.ConnectorArtifacts)
	usageHandler := NewUsageHandler(usagesvc.New(cfg.DB, cfg.Logger.Named("usage")))
	settingsSvc := settingssvc.New(cfg.DB, catalogsvc.New(cfg.DB, cfg.Logger.Named("settings-catalog")), cfg.Logger.Named("settings"))
	sysSettingsHandler := newSettingsHandler(settingsHandlerDeps{Svc: settingsSvc})

	// Health check (public, no auth — reverse proxies and orchestrators need
	// to hit this without credentials). 200 if DB+S3 reachable, 503 otherwise.
	healthH := newHealthHandler(cfg.DB, cfg.S3Client, cfg.Logger.Named("health"))
	r.Get("/health", healthH.Check)

	// WebSocket endpoint authenticates with the HttpOnly access cookie and an
	// exact configured Origin before upgrading.
	wsHandler := NewWSHandler(cfg.DB, cfg.Hub, cfg.Handler, cfg.JWTSecret, cfg.PublicURL, cfg.Logger.Named("ws"))
	r.Get("/ws", wsHandler.Upgrade)

	relayH := &relayHandler{
		db:          cfg.DB,
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
		r.Post("/logout", authHandler.Logout)
		r.Post("/device/begin", deviceLoginH.Begin)
		r.Post("/device/poll", deviceLoginH.Poll)

		// Passkey login ceremony (public). Begin returns a challenge +
		// ceremony id; finish verifies the assertion and issues tokens.
		r.Post("/passkey/login/begin", passkeyHandler.LoginBegin)
		r.Post("/passkey/login/finish", passkeyHandler.LoginFinish)

		// Authenticated: change password, relay code
		r.Group(func(r chi.Router) {
			r.Use(auth.Middleware(cfg.JWTSecret))
			r.Use(auth.LiveSessionMiddleware(cfg.DB))
			r.Post("/change-password", authHandler.ChangePassword)
			r.Post("/relay-code", relayH.GenerateCode)
		})
	})

	// Credential, bridge, and identity handlers. The connections service
	// takes function-typed deps for MCP discovery + auth injection so it
	// doesn't have to depend on the goai/mcp client directly.
	credSvcDiscovery := func(ctx context.Context, serverURL string, authInjection []byte, creds string) ([]connsvc.ToolInfo, string, error) {
		tools, instructions, err := agentapi.DiscoverMCPTools(ctx, cfg.HTTPNetwork.Client(60*time.Second), serverURL, authInjection, creds)
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
		func(ctx context.Context, serverURL string) (*oauth.DiscoveryResult, error) {
			return agentapi.DiscoverMCPAuth(ctx, cfg.HTTPNetwork.Client(30*time.Second), serverURL)
		},
		agentapi.InjectAuth,
		cfg.HTTPNetwork.Client(30*time.Second),
		cfg.HTTPNetwork,
	))
	brH := newBridgeHandler(bridgessvc.New(
		cfg.DB, cfg.Secrets, cfg.TelegramDriver,
		cfg.BridgeManager, cfg.Logger.Named("bridges"),
	))
	idH := newIdentityHandler(
		identitysvc.New(
			cfg.DB, cfg.Secrets,
			telegramIdentityAdapter{d: cfg.TelegramDriver},
			cfg.Logger.Named("identity"),
		),
		cfg.JWTSecret, // reuse JWT secret for HMAC
		cfg.PublicURL,
	)

	catalogH := newCatalogHandler(catalogsvc.New(cfg.DB, cfg.Logger.Named("catalog")))

	// Public endpoints (no JWT required)
	r.Get("/api/v1/credentials/oauth/callback", credH.OAuthCallback)
	r.Get("/auth-external", idH.AuthExternal)
	r.Get("/.well-known/airlock-agent-sdk", getAgentSDKInfo(cfg.PublicURL))
	r.Route("/api/hosts/v1", func(r chi.Router) {
		r.Post("/enroll/device-code", hostProtocol.Begin)
		r.Post("/enroll/complete", hostProtocol.CompleteEnrollment)
		r.Post("/sync", hostProtocol.Sync)
		r.Post("/connectors/inventory", hostProtocol.ConnectorInventory)
		r.Post("/work/poll", hostProtocol.Poll)
		r.Post("/management/{jobID}/events", hostProtocol.ManagementEvent)
		r.Post("/management/{jobID}/complete", hostProtocol.ManagementComplete)
		r.Post("/connectors/{connectorID}/jobs/{jobID}/events", hostProtocol.ConnectorEvent)
		r.Post("/connectors/{connectorID}/jobs/{jobID}/complete", hostProtocol.ConnectorComplete)
	})

	// OAuth Authorization Server handler — built once and reused by
	// both the top-level unauthenticated routes (/.well-known, /oauth/*)
	// and the /api/v1/oauth/* routes that require a user JWT.
	oauthH := newOAuthServerHandler(cfg.DB, cfg.JWTSecret, cfg.PublicURL, cfg.Logger.Named("oauth"))

	// Authenticated API routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(auth.Middleware(cfg.JWTSecret))
		r.Use(auth.LiveSessionMiddleware(cfg.DB))
		r.Use(identityLogger)
		// Block a must_change_password user from everything except the
		// account-securing endpoints until they secure the account.
		r.Use(securedAccountGate)

		r.Get("/me", authHandler.Me)
		r.Patch("/me", usersHandler.UpdateMe)
		r.Get("/sessions", authHandler.ListSessions)
		r.Delete("/sessions/{id}", authHandler.RevokeSession)

		// Per-user passkeys + password. Self-service: any authenticated user
		// manages their own; not admin-gated. The register endpoints are on
		// the secured-account allowlist so a forced-change user can enroll a
		// passkey to secure the account.
		r.Route("/me/passkeys", func(r chi.Router) {
			r.Get("/", passkeyHandler.List)
			r.With(auth.RequireRecentAuthentication).Post("/register/begin", passkeyHandler.RegisterBegin)
			r.With(auth.RequireRecentAuthentication).Post("/register/finish", passkeyHandler.RegisterFinish)
			r.With(auth.RequireRecentAuthentication).Patch("/{id}", passkeyHandler.Rename)
			r.With(auth.RequireRecentAuthentication).Delete("/{id}", passkeyHandler.Delete)
		})
		r.With(auth.RequireRecentAuthentication).Post("/me/password", passkeyHandler.SetPassword)
		r.With(auth.RequireRecentAuthentication).Delete("/me/password", passkeyHandler.RemovePassword)

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
			r.Use(auth.RequireTenantRole(authz.RequiredTenantRole(authz.TenantUserManage)))
			r.Get("/", usersHandler.List)
			r.Post("/", usersHandler.Create)
			r.Patch("/{userID}", usersHandler.UpdateRole)
			r.Delete("/{userID}", usersHandler.Delete)
		})

		// System settings. GET is readable by any authenticated user so the
		// Agent Create flow can prefill system defaults; PUT stays admin-only.
		r.Get("/settings", sysSettingsHandler.Get)
		r.With(auth.RequireTenantRole(authz.RequiredTenantRole(authz.TenantSettingsUpdate))).Put("/settings", sysSettingsHandler.Update)
		r.Get("/agent-sdk", getAgentSDKInfo(cfg.PublicURL))
		r.Post("/device-login/inspect", deviceLoginH.Inspect)
		r.Post("/device-login/approve", deviceLoginH.Approve)
		r.Post("/device-login/deny", deviceLoginH.Deny)
		r.Post("/host-enrollments/inspect", hostsHandler.InspectEnrollment)
		r.Post("/host-enrollments/approve", hostsHandler.ApproveEnrollment)
		r.Post("/host-enrollments/deny", hostsHandler.DenyEnrollment)
		r.Get("/hosts", hostsHandler.List)
		r.Get("/hosts/{hostID}", hostsHandler.Get)
		r.Post("/hosts/{hostID}/shell", hostsHandler.Shell)
		r.Post("/hosts/{hostID}/connectors", hostsHandler.Install)
		r.Get("/host-management-jobs/{jobID}", hostsHandler.GetJob)
		r.Post("/connectors/{connectorID}/update", hostsHandler.UpdateConnector)
		r.Post("/connectors/{connectorID}/remove", hostsHandler.RemoveConnector)
		r.Post("/connectors/{connectorID}/rollback", hostsHandler.RollbackConnector)

		r.Get("/connectors", connectorsHandler.List)
		r.Get("/connectors/{connectorID}", connectorsHandler.Get)
		r.Put("/connectors/{connectorID}/labels", connectorsHandler.SetLabels)
		r.Get("/connector-target-groups", connectorsHandler.ListGroups)
		r.Post("/connector-target-groups", connectorsHandler.CreateGroup)
		r.Post("/connector-target-groups/{groupID}/members", connectorsHandler.AddGroupMember)
		r.Delete("/connector-target-groups/{groupID}/members/{connectorID}", connectorsHandler.RemoveGroupMember)
		r.Post("/connector-orchestrations", connectorsHandler.CreateOrchestration)
		r.Get("/connector-orchestrations/{orchestrationID}", connectorsHandler.GetOrchestration)
		r.Post("/connector-orchestrations/{orchestrationID}/advance", connectorsHandler.AdvanceOrchestration)
		r.Delete("/connector-orchestrations/{orchestrationID}", connectorsHandler.CancelOrchestration)

		// Provider management (admin/owner only)
		r.Route("/providers", func(r chi.Router) {
			// List is manager+ (model selection needs the non-secret provider
			// list); mutations stay admin. The service re-gates either way.
			r.With(auth.RequireTenantRole(authz.RequiredTenantRole(authz.TenantProviderView))).Get("/", providersHandler.List)
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireTenantRole(authz.RequiredTenantRole(authz.TenantProviderManage)))
				r.Post("/", providersHandler.Create)
				r.Route("/{id}", func(r chi.Router) {
					r.Patch("/", providersHandler.Update)
					r.Delete("/", providersHandler.Delete)
					r.Get("/models", providersHandler.ListModels)
					r.Put("/models", providersHandler.ReplaceModels)
					r.Post("/discover-models", providersHandler.DiscoverModels)
				})
			})
		})

		// Agent resource needs (manifest) + binding. The service gates each op
		// (list = member; candidates/bind/create = agent admin per resource type).
		r.Get("/agents/{agentID}/needs", needsHandler.ListNeeds)
		r.Get("/agents/{agentID}/needs/{type}/{slug}/candidates", needsHandler.ListCandidates)
		r.Get("/agents/{agentID}/needs/connector/{slug}/target-groups", needsHandler.ListConnectorTargetGroupCandidates)
		r.Get(connectorArtifactsListRoute, connectorArtifactsHandler.List)
		r.Post(connectorArtifactDownloadRoute, connectorArtifactsHandler.Download)
		r.Post("/agents/{agentID}/needs/{type}/{slug}/bind", needsHandler.BindNeed)
		r.Post("/agents/{agentID}/needs/connector/{slug}/bind-group", needsHandler.BindConnectorGroup)
		r.Delete("/agents/{agentID}/needs/{type}/{slug}/bind", needsHandler.UnbindNeed)
		r.Post("/agents/{agentID}/needs/{type}/{slug}/create", needsHandler.CreateForNeed)

		// Reusable resource inventory and lifecycle. Each service method checks
		// the caller's effective resource capabilities.
		r.Get("/resources", resourcesHandler.List)
		r.Post("/resources/connections", credH.CreateConnectionResource)
		r.Get("/usage", usageHandler.Get)
		r.Post("/resources/{type}/{id}/revoke", resourcesHandler.Revoke)
		r.Patch("/resources/{type}/{id}", resourcesHandler.Rename)
		r.Delete("/resources/{type}/{id}", resourcesHandler.Delete)
		r.Get("/resources/{type}/{id}/consumers", resourcesHandler.Consumers)
		r.Get("/resources/{type}/{id}/grants", resourcesHandler.ListGrants)
		r.Put("/resources/{type}/{id}/grants/{userID}", resourcesHandler.UpsertGrant)
		r.Delete("/resources/{type}/{id}/grants/{userID}", resourcesHandler.DeleteGrant)
		r.Post("/resources/{type}/{id}/transfer", resourcesHandler.Transfer)

		// Model entitlements (admin only).
		r.Route("/model-grants", func(r chi.Router) {
			r.Use(auth.RequireTenantRole(authz.RequiredTenantRole(authz.TenantModelGrantManage)))
			r.Get("/", grantsHandler.ListModelGrants)
			r.Get("/usage", grantsHandler.ModelUsage)
			r.Post("/", grantsHandler.GrantModel)
			r.Delete("/{id}", grantsHandler.RevokeModelGrant)
		})

		// Catalog (read-only, any authenticated user)
		r.Get("/catalog/providers", catalogH.ListProviders)
		r.Get("/catalog/models", catalogH.ListModels)
		r.Get("/catalog/capabilities", catalogH.ListCapabilities)

		// Credential management
		r.Post("/credentials/oauth/start", credH.OAuthStart)
		r.Post("/credentials/mcp/oauth/start", credH.MCPOAuthStart)
		r.Post("/resource-authorizations/start", credH.StartAuthorizationForNeed)

		// Agent management (Phase 6)
		agH := newAgentsHandler(
			agentssvc.New(
				cfg.DB, cfg.BuildService, cfg.Dispatcher,
				cfg.Containers, cfg.BridgeManager,
				cfg.Secrets,
				cfg.Jobs.Wake,
				cfg.Logger.Named("agents"),
			),
			memberssvc.New(cfg.DB, cfg.Logger.Named("members")),
			cfg.PublicURL,
			cfg.AgentBaseURL,
		)
		publishRunTerminal := func(ctx context.Context, agentID, runID uuid.UUID, status, errMsg string) {
			agentapi.PublishRunTerminal(ctx, cfg.PubSub, agentID, runID, status, errMsg)
		}
		runsService := runssvc.New(cfg.DB, cfg.Dispatcher, cfg.Jobs, publishRunTerminal, cfg.Logger.Named("runs"))
		rH := newRunsHandler(runsService, cfg.S3Client, cfg.Logger.Named("runs"))
		jobsH := newJobsHandler(cfg.Jobs)
		cH := &conversationsHandler{
			svc: convsvc.New(cfg.DB, cfg.S3Client, cfg.Logger.Named("conversations"),
				func(parts []byte, agentID string) []string {
					return agentapi.ExtractCanonicalKeys(parts, agentID)
				}),
			runsSvc:      runsService,
			db:           cfg.DB,
			dispatcher:   cfg.Dispatcher,
			promptProxy:  cfg.PromptProxy,
			bridgeMgr:    cfg.BridgeManager,
			pubsub:       cfg.PubSub,
			s3:           cfg.S3Client,
			convLocks:    newConvMutexMap(),
			agentBaseURL: cfg.AgentBaseURL,
			logger:       cfg.Logger.Named("conversations"),
		}
		mH := newModelsHandler(modelssvc.New(cfg.DB, catalogsvc.New(cfg.DB, cfg.Logger.Named("models-catalog")), cfg.Dispatcher.RefreshAgent, cfg.Logger.Named("models")))
		r.Get("/models/allowed", mH.AllowedModels)
		siblingsH := newSiblingsHandler(siblingssvc.New(cfg.DB, cfg.Dispatcher, cfg.Logger.Named("siblings")))

		// Wire post-upgrade notifications to conversations handler.
		cfg.BuildService.SetUpgradeNotifier(cH)

		// Managed-bot sessions. The Telegram manager is a capability on a
		// bridge (is_manager), so there's no separate poller: the manager
		// bridge's own poll loop surfaces ManagedBotCreated events, which the
		// BridgeManager hands to the bridges service to materialize into a
		// bridge. The deep-link flow resolves the manager bridge's username
		// (with a live can_manage_bots re-check) from the same service.
		// Built before the sysagent so its create_tg_bot tool can call it.
		managerBridgesSvc := bridgessvc.New(cfg.DB, cfg.Secrets, cfg.TelegramDriver, cfg.BridgeManager, cfg.Logger.Named("managed-bridges"))
		cfg.BridgeManager.AttachManagedBotIngest(managerBridgesSvc.IngestManagedBotCreated)
		managedBotsSvc := managedbotssvc.New(managedbotssvc.Deps{
			DB:                    cfg.DB,
			ManagerBridgeUsername: managerBridgesSvc.ManagerBridgeUsername,
			Logger:                cfg.Logger.Named("managedbots"),
		})
		managedBotsH := newManagedBotSessionsHandler(managedBotsSvc)

		// In-airlock system agent: operator-facing chat that wraps
		// every per-domain service in typed Go tools. Per-domain
		// services are fresh instances (stateless wrappers; identical
		// to the handler-owned ones above modulo logger name).
		sysagentSvc := sysagent.New(sysagent.Deps{
			DB:                 cfg.DB,
			Encryptor:          cfg.Secrets,
			PubSub:             cfg.PubSub,
			PublicURL:          cfg.PublicURL,
			ProviderHTTPClient: cfg.ProviderEndpointHTTPClient,
			Logger:             cfg.Logger.Named("sysagent"),
			Agents: agentssvc.New(
				cfg.DB, cfg.BuildService, cfg.Dispatcher,
				cfg.Containers, cfg.BridgeManager,
				cfg.Secrets,
				cfg.Jobs.Wake,
				cfg.Logger.Named("sysagent-agents"),
			),
			Bridges: bridgessvc.New(
				cfg.DB, cfg.Secrets, cfg.TelegramDriver,
				cfg.BridgeManager, cfg.Logger.Named("sysagent-bridges"),
			),
			Catalog: catalogsvc.New(cfg.DB, cfg.Logger.Named("sysagent-catalog")),
			Conns: connsvc.New(
				cfg.DB, cfg.Secrets, cfg.OAuthClient, cfg.PublicURL,
				cfg.Dispatcher.RefreshAgent, cfg.Logger.Named("sysagent-conns"),
				credSvcDiscovery,
				func(ctx context.Context, serverURL string) (*oauth.DiscoveryResult, error) {
					return agentapi.DiscoverMCPAuth(ctx, cfg.HTTPNetwork.Client(30*time.Second), serverURL)
				},
				agentapi.InjectAuth, cfg.HTTPNetwork.Client(30*time.Second), cfg.HTTPNetwork,
			),
			GitCreds:    gitcredssvc.New(cfg.DB, cfg.Secrets, cfg.Logger.Named("sysagent-gitcreds")),
			ManagedBots: managedBotsSvc,
			Members:     memberssvc.New(cfg.DB, cfg.Logger.Named("sysagent-members")),
			Runs:        runssvc.New(cfg.DB, cfg.Dispatcher, cfg.Jobs, publishRunTerminal, cfg.Logger.Named("sysagent-runs")),
			Siblings:    siblingssvc.New(cfg.DB, cfg.Dispatcher, cfg.Logger.Named("sysagent-siblings")),
			Users:       userssvc.New(cfg.DB, cfg.BridgeManager, cfg.Logger.Named("sysagent-users")),
		})
		// Route post-upgrade notifications triggered from sysagent
		// conversations back to the conversation (NotifyUpgradeComplete injects
		// the [Upgrade succeeded] event + auto-resumes the LLM).
		// Conversation-origin upgrades still flow through the
		// cH-side notifier above.
		cfg.BuildService.SetUpgradeSystemNotifier(sysagentSvc)
		// Same path for initial builds kicked off from a sysagent
		// create_agent tool (NotifyBuildComplete → [Build succeeded] + resume).
		cfg.BuildService.SetBuildSystemNotifier(sysagentSvc)
		// Bridge delivery for those completion follow-ups: a bridge-originated
		// create/upgrade has no live inbound update, so the notifier asks the
		// bridge manager to run the auto-resume through the same sink the
		// inbound poller uses (streams the reply + renders confirmation buttons
		// for any gated tool the resume chains into).
		sysagentSvc.SetBridgeResumer(cfg.BridgeManager)
		sysagentH := newSysagentHandler(sysagentSvc)

		// Wire sysagent into the bridge manager so system-bridge
		// (br.IsSystem) inbound DMs route into the in-airlock chat
		// surface instead of the agent path. *sysagent.Service satisfies
		// trigger.SysagentRuntime directly — same method names + types,
		// the interface lives in trigger to break the import cycle
		// (sysagent → service/agents → trigger).
		cfg.BridgeManager.AttachSysagent(sysagentSvc)

		r.Route("/agents", func(r chi.Router) {
			r.Get("/", agH.List)
			r.Get("/all", agH.ListAll) // admin governance: every agent in the tenant
			r.Post("/", agH.Create)

			r.Route("/{agentID}", func(r chi.Router) {
				r.Get("/", agH.Get)
				r.Patch("/", agH.Update)
				r.Delete("/", agH.Delete)
				r.Head("/source", agH.SourceState)
				r.Get("/source", agH.DownloadSource)
				r.Put("/source", agH.UploadSource)
				r.Post("/clone", agH.Clone)
				r.Post("/transfer", agH.TransferOwnership)
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
				r.Get("/builds/{buildID}/job-blockers", jobsH.ListBuildBlockers)
				r.Get("/builds/{buildID}", agH.GetBuild)
				r.Post("/builds/cancel", agH.CancelBuild)

				// External git remote (optional, per agent)
				r.Get("/git", agH.GetGitConfig)
				r.Post("/git/connect", agH.ConnectGit)
				r.Post("/git/disconnect", agH.DisconnectGit)

				// Runs
				r.Get("/runs", rH.ListRuns)
				r.Get("/jobs", jobsH.ListJobs)
				r.Get("/job-handlers", jobsH.ListHandlers)

				// Webhooks, Schedules & Functions
				r.Get("/webhooks", agH.ListWebhooks)
				r.Get("/schedules", agH.ListSchedules)
				r.Post("/schedules/{slug}/fire", agH.FireSchedule)
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
				r.Get("/siblings/inbound", siblingsH.ListInbound)
				r.Post("/siblings", siblingsH.Add)
				r.Patch("/siblings/{siblingID}", siblingsH.UpdateMaxAccess)
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

		// System-agent conversations: operator chat surface, per-user.
		// Conversations are not shared; the service enforces ownership at
		// every entry point.
		r.Route("/system/conversations", func(r chi.Router) {
			r.Get("/", sysagentH.ListConversations)
			r.Post("/", sysagentH.CreateConversation)
			r.Get("/{conversationID}", sysagentH.GetConversation)
			r.Delete("/{conversationID}", sysagentH.DeleteConversation)
			r.Post("/{conversationID}/prompt", sysagentH.Prompt)
		})
		// Activity view across the operator's own sysagent runs (all
		// conversations). Owner-scoped query inside the service.
		r.Get("/system/runs", sysagentH.ListRuns)

		// Top-level conversation and run routes (not nested under agent).
		// Topic subscription is conversation-scoped: the conversation that
		// subscribes is the one that receives the topic's notifications.
		r.Get("/conversations", cH.ListAllConversations)
		r.Get("/conversations/feed", cH.FeedConversations)
		r.Get("/conversations/{convID}", cH.GetConversation)
		r.Get("/conversations/{convID}/messages", cH.ListConversationMessages)
		r.Delete("/conversations/{convID}", cH.DeleteConversation)
		r.Get("/conversations/{convID}/topics", cH.ListTopics)
		r.Post("/conversations/{convID}/topics/{slug}/subscribe", cH.SubscribeTopic)
		r.Delete("/conversations/{convID}/topics/{slug}/subscribe", cH.UnsubscribeTopic)
		r.Get("/runs/{runID}", rH.GetRun)
		r.Get("/runs/{runID}/logs", rH.GetRunLogs)
		r.Delete("/runs/{runID}", rH.CancelRun)
		r.Get("/jobs/{jobID}", jobsH.GetJob)
		r.Delete("/jobs/{jobID}", jobsH.CancelJob)
		r.Post("/jobs/{jobID}/retry", jobsH.RetryJob)

		// Bridge management
		r.Route("/bridges", func(r chi.Router) {
			r.Get("/", brH.ListBridges)
			r.Post("/", brH.CreateBridge)
			r.Put("/{bridgeID}", brH.UpdateBridge)
			r.Delete("/{bridgeID}", brH.DeleteBridge)

			// Managed-bot create flow (Telegram Bot API 9.6).
			// Sessions correlate an airlock "Create new bot" click
			// to the eventual ManagedBotCreated callback received
			// by the manager bot poller. The /start handler refuses
			// requests from un-linked or mismatched-identity users,
			// so ManagedBotCreated only fires for the right caller
			// — no orphan-claim path is exposed.
			r.Post("/managed/sessions", managedBotsH.Create)
		})

		// Platform identity management
		r.Get("/link-identity/preview", idH.LinkIdentityPreview)
		r.Post("/link-identity", idH.LinkIdentity)
		r.Route("/identities", func(r chi.Router) {
			r.Get("/", idH.ListIdentities)
			r.Delete("/{identityID}", idH.UnlinkIdentity)
		})
	})

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
	ah := agentapi.New(agentapi.Config{
		DB:                     cfg.DB,
		Encryptor:              cfg.Secrets,
		OAuthClient:            cfg.OAuthClient,
		S3:                     cfg.S3Client,
		Files:                  fileService,
		Jobs:                   cfg.Jobs,
		ConnectorJobs:          connectorJobsService,
		ConnectorDirectories:   connectorDirectoriesService,
		ConnectorOrchestration: connectorOrchestrationService,
		Builder:                cfg.BuildService,
		PubSub:                 cfg.PubSub,
		BridgeMgr:              cfg.BridgeManager,
		Scheduler:              cfg.Scheduler,
		PublicURL:              cfg.PublicURL,
		AgentBaseURL:           cfg.AgentBaseURL,
		LLMProxyURL:            cfg.LLMProxyURL,
		ForceInlineAttachments: cfg.ForceInlineAttachments,
		HTTPNetwork:            cfg.HTTPNetwork,
		JWTSecret:              cfg.JWTSecret,
		Dispatcher:             cfg.Dispatcher,
		Logger:                 cfg.Logger.Named("agent-api"),
	})
	integrationsH := newIntegrationsHandler(integrationssvc.New(cfg.DB, ah))
	r.Route("/api/v1/agents/{agentID}/integrations", func(r chi.Router) {
		r.Use(auth.Middleware(cfg.JWTSecret))
		r.Use(auth.LiveSessionMiddleware(cfg.DB))
		r.Use(identityLogger)
		r.Use(securedAccountGate)
		r.Use(integrationUserContext)
		mountIntegrationRoutes(r, integrationsH)
	})
	r.Route("/api/codegen/integrations", func(r chi.Router) {
		r.Use(codegenIntegrationAuth(cfg.DB))
		mountIntegrationRoutes(r, integrationsH)
	})
	// MCP server endpoint — A2A entry point + external MCP client
	// entry point. Mounted at top level (outside the /api/agent
	// agent-JWT route group) because its auth model is multi-principal
	// (user JWT / agent JWT / OAuth-issued access token). The
	// /public-mcp route serves the same JSON-RPC interface anonymously,
	// gated by `agent.allow_public_mcp`.
	mcp := agentapi.NewMCPServer(cfg.Dispatcher, cfg.PubSub, cfg.Logger.Named("mcp"))
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
		r.Use(auth.AgentMiddleware(cfg.JWTSecret, dbq.New(cfg.DB.Pool())))
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
		r.Post("/jobs", ah.EnqueueJob)
		r.Get("/jobs", ah.ListJobs)
		r.Get("/jobs/{jobID}", ah.GetJob)
		r.Put("/jobs/{jobID}/progress", ah.UpdateJobProgress)
		r.Delete("/jobs/{jobID}", ah.CancelJob)
		r.Post("/topic/{slug}/subscribe", ah.TopicSubscribe)
		r.Delete("/topic/{slug}/subscribe", ah.TopicUnsubscribe)
		r.Post("/mcp/{slug}/tools/call", ah.MCPToolCall)
		r.Post("/connectors/{needSlug}/commands/{operation}", ah.ConnectorCommand)
		r.Get("/connectors/{needSlug}/directories/{directory}/list", ah.ConnectorDirectoryList)
		r.Get("/connectors/{needSlug}/directories/{directory}/stat", ah.ConnectorDirectoryStat)
		r.Get("/connectors/{needSlug}/directories/{directory}/read", ah.ConnectorDirectoryRead)
		r.Post("/connectors/{needSlug}/directories/{directory}/write", ah.ConnectorDirectoryWrite)
		r.Delete("/connectors/{needSlug}/directories/{directory}/delete", ah.ConnectorDirectoryDelete)
		r.Post("/connectors/{needSlug}/directories/{directory}/move", ah.ConnectorDirectoryMove)
		r.Post("/connectors/{needSlug}/directories/{directory}/import", ah.ConnectorDirectoryImport)
		r.Post("/connectors/{needSlug}/directories/{directory}/export", ah.ConnectorDirectoryExport)
		r.Post("/connectors/{needSlug}/jobs/{operation}", ah.StartConnectorJob)
		r.Get("/connectors/{needSlug}/jobs/{jobID}", ah.GetConnectorJob)
		r.Delete("/connectors/{needSlug}/jobs/{jobID}", ah.CancelConnectorJob)
		r.Post("/connectors/{needSlug}/orchestrations", ah.CreateConnectorOrchestration)
		r.Get("/connectors/{needSlug}/orchestrations/{orchestrationID}", ah.GetConnectorOrchestration)
		r.Delete("/connectors/{needSlug}/orchestrations/{orchestrationID}", ah.CancelConnectorOrchestration)
		r.Put("/env-vars/{slug}", ah.UpsertEnvVar)
		r.Get("/env-vars/{slug}", ah.GetEnvVarValue)
		// Seal/unseal: airlock encrypts/decrypts on the agent's behalf, bound
		// to the agent's identity (AAD) so the agent can persist secrets it
		// generates (e.g. session tokens) in its own DB as ciphertext.
		r.Post("/seal", ah.Seal)
		r.Post("/unseal", ah.Unseal)
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
		handler = SubdomainProxy(cfg.AgentDomain, cfg.DB, cfg.S3Client, fileService, cfg.Dispatcher, cfg.BridgeManager, cfg.JWTSecret, cfg.PublicURL, r)
	}
	handler = zapRecoverer(handler)
	handler = requestLogger(cfg.Logger)(handler)
	handler = RealIP(cfg.RealIP)(handler)
	handler = chimw.RequestID(handler)
	handler = chimw.Recoverer(handler)
	return handler
}

func platformCORSOptions(publicURL string) cors.Options {
	return cors.Options{
		AllowedOrigins:   []string{configuredOrigin(publicURL)},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}
}
