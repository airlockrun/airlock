package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/airlockrun/airlock/api"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"golang.org/x/term"
)

func runServe(_ []string) {
	cfg := config.Load()

	// Create logger: console format for terminals, JSON for pipes/containers.
	// LOG_FORMAT=json forces JSON output; LOG_LEVEL=debug enables debug verbosity.
	var logger *zap.Logger
	useConsole := term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("LOG_FORMAT") != "json"
	if useConsole {
		zapCfg := zap.NewDevelopmentConfig()
		if os.Getenv("LOG_LEVEL") != "debug" {
			zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		}
		// Only show stacktraces for panics, not regular errors
		logger = zap.Must(zapCfg.Build(zap.AddStacktrace(zap.DPanicLevel)))
	} else {
		logger = zap.Must(zap.NewProduction())
	}
	defer logger.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Connect to database
	database := db.New(ctx, cfg.DatabaseURL)
	defer database.Close()

	// Run migrations
	if err := db.RunMigrations(cfg.DatabaseURL); err != nil {
		logger.Fatal("migrations failed", zap.Error(err))
	}
	logger.Info("migrations up to date")

	// Seed system settings from INIT_ env vars (one-time: only writes if DB value is empty).
	{
		q := dbq.New(database.Pool())
		settings, err := q.GetSystemSettings(ctx)
		if err != nil {
			logger.Fatal("read system settings failed", zap.Error(err))
		}
		initPublicURL := os.Getenv("INIT_PUBLIC_URL")
		initAgentDomain := os.Getenv("INIT_AGENT_DOMAIN")
		if settings.PublicUrl == "" && initPublicURL != "" {
			if _, err := q.UpdateSystemSettings(ctx, dbq.UpdateSystemSettingsParams{
				PublicUrl:   initPublicURL,
				AgentDomain: initAgentDomain,
			}); err != nil {
				logger.Fatal("seed system settings failed", zap.Error(err))
			}
			logger.Info("system settings seeded from env",
				zap.String("public_url", initPublicURL),
				zap.String("agent_domain", initAgentDomain))
		}
	}

	// Ensure an activation code exists on first run — generate if missing,
	// log it, and write to a file for docker-compose users to `cat`.
	// Safe to run from multiple replicas: SetActivationCode only writes
	// when the column is NULL, and we always re-read the winning value.
	if err := ensureActivationCode(ctx, database, cfg.ActivationCodeFile, logger); err != nil {
		logger.Fatal("activation code setup failed", zap.Error(err))
	}

	// S3/MinIO client
	s3Client := storage.NewS3Client(cfg)
	if err := s3Client.EnsureBucket(ctx); err != nil {
		logger.Fatal("s3: ensure bucket failed", zap.Error(err))
	}
	logger.Info("s3 connected")

	// Container manager
	containers := container.NewDockerManager(cfg, logger.Named("container"))
	defer containers.Close()
	logger.Info("docker manager ready")

	// Ensure /libs/ is materialized on the host. Always extracts from the
	// agent-builder image (so goose/templ are available); if AGENT_LIBS_PATH
	// is set, the owned libs (agentsdk/goai/sol) come from there for live
	// dev edits.
	libs, err := builder.EnsureLibs(ctx, cfg.AgentBuilderImage, cfg.AgentLibsPath, cfg.AgentLibsCacheDir, logger.Named("libs"))
	if err != nil {
		logger.Fatal("agent libs setup failed", zap.Error(err))
	}
	cfg.AgentLibsPath = libs.Owned
	cfg.AgentLibsExtPath = libs.Ext

	// s3Client is used by agent API routes

	// Decode encryption key(s)
	encKey, err := hex.DecodeString(cfg.EncryptionKey)
	if err != nil {
		logger.Fatal("ENCRYPTION_KEY: invalid hex", zap.Error(err))
	}
	var oldKeys [][]byte
	if cfg.EncryptionKeyOld != "" {
		oldKey, err := hex.DecodeString(cfg.EncryptionKeyOld)
		if err != nil {
			logger.Fatal("ENCRYPTION_KEY_OLD: invalid hex", zap.Error(err))
		}
		oldKeys = append(oldKeys, oldKey)
	}
	enc := crypto.New(encKey, oldKeys...)
	logger.Info("encryption configured")

	// Build service
	buildSvc := builder.New(cfg, database, containers, enc, logger.Named("builder"))
	if err := buildSvc.RecoverStuckOperations(ctx); err != nil {
		logger.Fatal("build service recovery failed", zap.Error(err))
	}
	logger.Info("build service ready")

	// Prune orphaned containers, stale images, and dead monorepo dirs on startup.
	{
		q := dbq.New(database.Pool())
		agents, err := q.ListAgents(ctx)
		if err != nil {
			logger.Fatal("list agents for prune failed", zap.Error(err))
		}
		validAgents := make(map[string]string, len(agents))
		for _, a := range agents {
			id := uuid.UUID(a.ID.Bytes).String()
			validAgents[id] = a.ImageRef
		}
		containers.PruneAgentResources(ctx, validAgents)
		pruneMonorepo(buildSvc.MonorepoPath(), validAgents, logger.Named("prune"))
	}

	// Warm Docker build cache in background — first agent build will be faster.
	go buildSvc.WarmBuildCache(ctx)
	// Warm the runtime go-mod / go-build volumes the build-prompt loop's
	// direct `go build` invocations consume (distinct cache from the one
	// above, which only seeds BuildKit's cache mount for `docker build`).
	go buildSvc.WarmRuntimeCaches(ctx)

	// Create Hub and PubSub
	hub := realtime.NewHub(logger.Named("hub"))
	pubsub := realtime.NewPubSub(hub, logger.Named("pubsub"))
	defer pubsub.Close()

	// Wire build events to PubSub
	buildSvc.SetEventPublisher(realtime.NewBuildEventPublisher(pubsub, hub))

	// Create WS handler
	wsHandler := realtime.NewHandler(database, hub, pubsub, logger.Named("handler"))

	// OIDC — initOIDC returns nil by default; wire in a provider to enable.
	oidc := initOIDC(ctx, cfg, database, cfg.JWTSecret, logger)

	// Trigger system
	dispatcher := trigger.NewDispatcher(cfg, database, containers, enc, logger.Named("dispatcher"))
	transcriptionResolver := trigger.NewTranscriptionResolver(database, enc)
	prompter := trigger.NewPromptProxy(dispatcher, database, s3Client, transcriptionResolver, logger.Named("prompt-proxy"))
	telegramDriver := trigger.NewTelegramDriver(logger.Named("telegram"))
	drivers := map[string]trigger.BridgeDriver{
		"telegram": telegramDriver,
	}
	bridgeMgr := trigger.NewBridgeManager(drivers, prompter, database, enc, cfg.JWTSecret, cfg.PublicURL, logger.Named("bridges"))
	scheduler := trigger.NewScheduler(dispatcher, database, logger.Named("scheduler"))

	// OAuth client (used by credential endpoints and refresh job)
	oauthClient := oauth.NewClient()

	// Reverse proxy real IP config
	realIPCfg := api.ParseRealIPConfig(cfg.ReverseProxyTrustedProxies, cfg.ReverseProxyLimit)
	if realIPCfg.Enabled() {
		logger.Info("real IP extraction enabled",
			zap.String("trusted_proxies", cfg.ReverseProxyTrustedProxies),
			zap.Int("limit", cfg.ReverseProxyLimit),
		)
	}

	// Build router
	router := api.NewRouter(api.RouterConfig{
		DB:             database,
		JWTSecret:      cfg.JWTSecret,
		OIDC:           oidc,
		PublicURL:      cfg.PublicURL,
		OAuthClient:    oauthClient,
		TelegramDriver: telegramDriver,
		Encryptor:      enc,
		S3Client:       s3Client,
		BuildService:   buildSvc,
		Dispatcher:     dispatcher,
		Scheduler:      scheduler,
		BridgeManager:  bridgeMgr,
		Containers:     containers,
		PromptProxy:    prompter,
		Hub:            hub,
		PubSub:         pubsub,
		Handler:        wsHandler,
		AgentDomain:            cfg.AgentDomain,
		LLMProxyURL:            cfg.LLMProxyURL,
		ForceInlineAttachments: cfg.ForceInlineAttachments,
		ActivationCodeFile:     cfg.ActivationCodeFile,
		RealIP:                 realIPCfg,
		Logger:                 logger,
	})

	// Start HTTP server
	srv := &http.Server{
		Addr:    cfg.ServerAddr,
		Handler: router,
	}

	go func() {
		logger.Info("server listening", zap.String("addr", cfg.ServerAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server error", zap.Error(err))
		}
	}()

	// Start background trigger services
	if err := scheduler.Start(ctx); err != nil {
		logger.Fatal("scheduler start failed", zap.Error(err))
	}
	defer scheduler.Stop()

	if err := bridgeMgr.Start(ctx); err != nil {
		logger.Fatal("bridge manager start failed", zap.Error(err))
	}
	defer bridgeMgr.Stop()

	// Token refresh job
	refreshJob := oauth.NewRefreshJob(database, enc, oauthClient, logger.Named("oauth-refresh"))
	go refreshJob.Run(ctx)

	// Event file cleanup — delete events/ prefix files older than 24h.
	go func() {
		cleanupLogger := logger.Named("event-cleanup")
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				objects, err := s3Client.ListObjects(ctx, "events/")
				if err != nil {
					cleanupLogger.Error("list events failed", zap.Error(err))
					continue
				}
				cutoff := time.Now().Add(-24 * time.Hour)
				deleted := 0
				for _, obj := range objects {
					if obj.LastModified.Before(cutoff) {
						if err := s3Client.DeleteObject(ctx, obj.Key); err != nil {
							cleanupLogger.Error("delete event file failed", zap.String("key", obj.Key), zap.Error(err))
						} else {
							deleted++
						}
					}
				}
				if deleted > 0 {
					cleanupLogger.Info("cleaned up event files", zap.Int("deleted", deleted))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Bridge tmp/ cleanup — delete agents/*/tmp/* blobs older than 3 days.
	// Bridge drivers stage incoming attachments under
	// agents/{agentID}/tmp/{uuid8}-{filename}; they're not referenced after
	// the LLM consumes them, so a time-based sweep is sufficient.
	go func() {
		cleanupLogger := logger.Named("tmp-cleanup")
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				objects, err := s3Client.ListObjects(ctx, "agents/")
				if err != nil {
					cleanupLogger.Error("list agents tmp failed", zap.Error(err))
					continue
				}
				cutoff := time.Now().Add(-72 * time.Hour)
				deleted := 0
				for _, obj := range objects {
					if !strings.Contains(obj.Key, "/tmp/") {
						continue
					}
					if obj.LastModified.Before(cutoff) {
						if err := s3Client.DeleteObject(ctx, obj.Key); err != nil {
							cleanupLogger.Error("delete tmp file failed", zap.String("key", obj.Key), zap.Error(err))
						} else {
							deleted++
						}
					}
				}
				if deleted > 0 {
					cleanupLogger.Info("cleaned up tmp files", zap.Int("deleted", deleted))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Runs compaction — nullify verbose JSONB/text on runs older than 30 days.
	// Aggregates (token counts, cost, duration, timestamps, status, error)
	// stay intact; verbose payload/actions/checkpoint/logs are dropped.
	go func() {
		cleanupLogger := logger.Named("runs-compact")
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		q := dbq.New(database.Pool())
		for {
			select {
			case <-ticker.C:
				cutoff := pgtype.Timestamptz{Time: time.Now().Add(-30 * 24 * time.Hour), Valid: true}
				n, err := q.CompactOldRuns(ctx, cutoff)
				if err != nil {
					cleanupLogger.Error("compact old runs failed", zap.Error(err))
					continue
				}
				if n > 0 {
					cleanupLogger.Info("compacted old runs", zap.Int64("rows", n))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Auth-lockout prune — drop failure rows older than 24h plus expired
	// lockout rows that have been quiet for 24h (so a subsequent first
	// failure resets the escalation tier to 0). Hourly is fine: the
	// failures table is small and the queries are pure DELETEs.
	go func() {
		cleanupLogger := logger.Named("auth-lockout-prune")
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		q := dbq.New(database.Pool())
		for {
			select {
			case <-ticker.C:
				if n, err := q.PruneAuthFailures(ctx); err != nil {
					cleanupLogger.Error("prune auth_failures failed", zap.Error(err))
				} else if n > 0 {
					cleanupLogger.Info("pruned auth failures", zap.Int64("rows", n))
				}
				if n, err := q.PruneStaleAuthLockouts(ctx); err != nil {
					cleanupLogger.Error("prune auth_lockouts failed", zap.Error(err))
				} else if n > 0 {
					cleanupLogger.Info("pruned stale auth lockouts", zap.Int64("rows", n))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Fatal("server shutdown failed", zap.Error(err))
	}
	logger.Info("server stopped")
}

// ensureActivationCode runs on startup. If the system isn't activated yet,
// it guarantees an activation code exists in DB (generating one if missing),
// logs it, and writes it to filePath so `docker compose` users can grab it
// with a single `cat`. On a fresh first run the file is created; on a
// subsequent restart where a code already exists, the file is overwritten
// with the same value (in case someone deleted it). Once a tenant exists,
// the code has already been consumed and the file is removed.
func ensureActivationCode(ctx context.Context, database *db.DB, filePath string, logger *zap.Logger) error {
	q := dbq.New(database.Pool())

	exists, err := q.TenantExists(ctx)
	if err != nil {
		return fmt.Errorf("check tenant exists: %w", err)
	}
	if exists {
		// Already activated. Remove any stale activation file from a previous
		// first-run so the secret doesn't linger on disk.
		if filePath != "" {
			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				logger.Warn("failed to remove stale activation file", zap.String("path", filePath), zap.Error(err))
			}
		}
		return nil
	}

	settings, err := q.GetSystemSettings(ctx)
	if err != nil {
		return fmt.Errorf("get system settings: %w", err)
	}

	if !settings.ActivationCode.Valid {
		var buf [16]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return fmt.Errorf("generate activation code: %w", err)
		}
		code := hex.EncodeToString(buf[:])
		// Only the first writer wins (WHERE activation_code IS NULL) — safe
		// under concurrent startup from multiple replicas.
		if _, err := q.SetActivationCode(ctx, pgtype.Text{String: code, Valid: true}); err != nil {
			return fmt.Errorf("set activation code: %w", err)
		}
		settings, err = q.GetSystemSettings(ctx)
		if err != nil {
			return fmt.Errorf("re-read system settings: %w", err)
		}
	}

	code := settings.ActivationCode.String
	logger.Warn("activation code ready — use it to create the first admin user",
		zap.String("code", code),
		zap.String("file", filePath))

	if filePath != "" {
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			logger.Warn("failed to create activation file dir", zap.String("path", filePath), zap.Error(err))
		} else if err := os.WriteFile(filePath, []byte(code+"\n"), 0o600); err != nil {
			logger.Warn("failed to write activation file", zap.String("path", filePath), zap.Error(err))
		}
	}

	return nil
}

// pruneMonorepo removes agent directories from the monorepo that don't
// correspond to any agent in the database. Uses builder.RemoveAgentCode
// so the deletion is properly committed to git.
func pruneMonorepo(repoPath string, validAgents map[string]string, logger *zap.Logger) {
	if repoPath == "" {
		return
	}
	agentsDir := filepath.Join(repoPath, "agents")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		logger.Warn("failed to read agents dir", zap.Error(err))
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, ok := validAgents[e.Name()]; !ok {
			logger.Info("removing orphaned agent code", zap.String("agent", e.Name()))
			if err := builder.RemoveAgentCode(repoPath, e.Name()); err != nil {
				logger.Warn("failed to remove agent code", zap.String("agent", e.Name()), zap.Error(err))
			}
		}
	}
}

