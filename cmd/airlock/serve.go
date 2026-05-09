package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
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

	// Kick off the models.dev catalog refresher: synchronous cache hydrate
	// (from /root/.cache/sol/models.json baked into the image, or builtin
	// fallback), then a background goroutine that does an immediate fetch
	// + 12h periodic refresh. Must run before any handler can reach the
	// catalog so the first capabilities request doesn't see stale data.
	solprovider.StartPeriodicRefresh(ctx)

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
	secretStore := secrets.NewLocal(crypto.New(encKey, oldKeys...))
	logger.Info("encryption configured")

	// Build service
	buildSvc := builder.New(cfg, database, containers, secretStore, logger.Named("builder"))
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

	// Trigger system
	dispatcher := trigger.NewDispatcher(cfg, database, containers, secretStore, logger.Named("dispatcher"))
	transcriptionResolver := trigger.NewTranscriptionResolver(database, secretStore)
	prompter := trigger.NewPromptProxy(dispatcher, database, s3Client, transcriptionResolver, logger.Named("prompt-proxy"))
	telegramDriver := trigger.NewTelegramDriver(logger.Named("telegram"))
	discordDriver := trigger.NewDiscordDriver(logger.Named("discord"))
	drivers := map[string]trigger.BridgeDriver{
		"telegram": telegramDriver,
		"discord":  discordDriver,
	}
	bridgeMgr := trigger.NewBridgeManager(drivers, prompter, database, secretStore, cfg.JWTSecret, cfg.PublicURL, logger.Named("bridges"))
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
		DB:                     database,
		JWTSecret:              cfg.JWTSecret,
		PublicURL:              cfg.PublicURL,
		OAuthClient:            oauthClient,
		TelegramDriver:         telegramDriver,
		DiscordDriver:          discordDriver,
		Secrets:                secretStore,
		S3Client:               s3Client,
		BuildService:           buildSvc,
		Dispatcher:             dispatcher,
		Scheduler:              scheduler,
		BridgeManager:          bridgeMgr,
		Containers:             containers,
		PromptProxy:            prompter,
		Hub:                    hub,
		PubSub:                 pubsub,
		Handler:                wsHandler,
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
	defer srv.Close()

	group, gctx := errgroup.WithContext(ctx)

	group.Go(func() error {
		logger.Info("server listening", zap.String("addr", cfg.ServerAddr))
		if err := srv.ListenAndServe(); err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("could not run server: %w", err)
			}

			return nil
		}

		return nil
	})

	// Start background trigger services
	if err := scheduler.Start(gctx); err != nil {
		logger.Fatal("scheduler start failed", zap.Error(err))
	}
	defer scheduler.Stop()

	if err := bridgeMgr.Start(gctx); err != nil {
		logger.Fatal("bridge manager start failed", zap.Error(err))
	}
	defer bridgeMgr.Stop()

	// Public-bridge session sweeper — finalize and delete public
	// conversations idle past the per-bridge TTL.
	trigger.StartPublicSweeper(gctx, database, bridgeMgr, 5*time.Minute, logger.Named("public-sweeper"))

	// Token refresh job
	refreshJob := oauth.NewRefreshJob(database, secretStore, oauthClient, logger.Named("oauth-refresh"))
	go refreshJob.Run(gctx)

	queries := dbq.New(database.Pool())

	group.Go(func() error {
		const period = time.Hour * 6

		return cleanS3Objects(gctx, logger, s3Client, period)
	})

	group.Go(func() error {
		const period = time.Hour * 6

		return cleanupAgentsObjects(gctx, logger, s3Client, queries, period)
	})

	group.Go(func() error {
		const period = time.Hour * 24

		return compacter(gctx, logger, queries, period)
	})

	group.Go(func() error {
		const period = time.Hour

		return authPruner(gctx, logger, queries, period)
	})

	group.Go(func() error {
		const period = time.Minute

		return sweeper(
			gctx,
			logger,
			queries,
			dispatcher,
			pubsub,
			period,
		)
	})

	group.Go(func() error {
		const period = time.Hour * 24

		return cachePruner(gctx, logger, queries, period)
	})

	group.Go(func() error {
		select {
		case <-ctx.Done():
		case <-gctx.Done():
		}

		sctx, scancel := context.WithTimeout(context.Background(), time.Second*10)
		defer scancel()

		if err := srv.Shutdown(sctx); err != nil {
			logger.Warn("server graceful shutdown failed", zap.Error(err))
		}

		return nil
	})

	if err := group.Wait(); err != nil {
		logger.Fatal("failed to run service", zap.Error(err))
	}

	logger.Info("stopping server")
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

// TODO(max): handle S3 failure properly: retry with backoff/reset timer.
func cleanS3Objects(
	ctx context.Context,
	lgr *zap.Logger,
	s3client *storage.S3Client,
	period time.Duration,
) error {
	if s3client == nil {
		return errors.New("expected *S3Client but got nil")
	}

	lgr = lgr.Named("event-cleanup")

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		objects, err := s3client.ListObjects(ctx, "events/")
		if err != nil {
			lgr.Error("list events failed", zap.Error(err))
			continue
		}

		cutoff := time.Now().Add(-24 * time.Hour)
		todelete := collectObjectsToDelete(objects, cutoff)

		deleted, err := s3client.DeleteObjects(ctx, todelete...)
		if err != nil {
			lgr.Error("deletion failed", zap.Int("deleted.count", deleted), zap.Error(err))
			continue
		}

		lgr.Info("deleted events", zap.Int("deleted.count", deleted))
	}
}

// Storage retention sweeper — delete objects under any directory the
// agent registered with retention_hours > 0, once they're older than
// the configured TTL. The framework auto-registers "tmp" at 72h
// (DirectoryOpts.RetentionHours), so the prior hardcoded "tmp/" sweep
// falls out naturally as a special case of this loop. Builders can
// opt arbitrary directories into the sweep by passing
// RetentionHours when calling RegisterDirectory.
//
// We list each opted-in S3 prefix per directory rather than scanning
// "agents/" once because per-directory TTLs vary and a single TTL on
// the union would either over- or under-keep depending on the
// shortest/longest opt-in. Cheap: the prefix lists are bounded by
// what the agent actually wrote.
func cleanupAgentsObjects(
	ctx context.Context,
	lgr *zap.Logger,
	s3client *storage.S3Client,
	queries *dbq.Queries,
	period time.Duration,
) error {
	if s3client == nil {
		return errors.New("expected *S3Client but got nil")
	}

	if queries == nil {
		return errors.New("expected *dbq.Queries but got nil")
	}

	lgr = lgr.Named("storage-retention-sweeper")

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		dirs, err := queries.ListDirectoriesWithRetention(ctx)
		if err != nil {
			lgr.Error("list directories with retention", zap.Error(err))

			continue
		}

		for _, dir := range dirs {
			agentUUID, err := uuid.FromBytes(dir.AgentID.Bytes[:])
			if err != nil {
				continue
			}

			prefix := "agents/" + agentUUID.String() + "/" + dir.Path + "/"

			objects, err := s3client.ListObjects(ctx, prefix)
			if err != nil {
				lgr.Error("list prefix failed", zap.String("prefix", prefix), zap.Error(err))

				continue
			}

			retention := time.Duration(dir.RetentionHours) * time.Hour
			cutoff := time.Now().Add(-retention)
			todelete := collectObjectsToDelete(objects, cutoff)

			deleted, err := s3client.DeleteObjects(ctx, todelete...)
			if err != nil {
				lgr.Error("deletion failed", zap.Int("deleted.count", deleted), zap.Error(err))
				continue
			}

			lgr.Info(
				"deleted events",
				zap.Int("deleted.count", deleted),
				zap.String("agent_id", dir.AgentID.String()),
				zap.String("path", dir.Path),
				zap.Duration("retention", retention),
			)
		}
	}
}

func collectObjectsToDelete(objects []storage.ObjectInfo, cutoff time.Time) []string {
	result := make([]string, 0, min(len(objects), 100)) // TODO(max): do we need that prealloc?

	for _, object := range objects {
		if object.LastModified.Before(cutoff) {
			result = append(result, object.Key)
		}
	}

	return result
}

// Runs compaction — nullify verbose JSONB/text on runs older than 30 days.
// Aggregates (token counts, cost, duration, timestamps, status, error)
// stay intact; verbose payload/actions/checkpoint/logs are dropped.
func compacter(
	ctx context.Context,
	lgr *zap.Logger,
	queries *dbq.Queries,
	period time.Duration,
) error {
	const days30 = 30 * 24 * time.Hour

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	if queries == nil {
		return errors.New("expected *dbq.Queries but got nil")
	}

	lgr = lgr.Named("runs-compact")

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		cutoff := pgtype.Timestamptz{
			Time:  time.Now().Add(-days30),
			Valid: true,
		}

		n, err := queries.CompactOldRuns(ctx, cutoff)
		if err != nil {
			lgr.Error("compact old runs failed", zap.Error(err))

			continue
		}

		lgr.Info("compacted old runs", zap.Int64("rows.count", n))
	}
}

// Auth-lockout prune — drop failure rows older than 24h plus expired lockout
// rows that have been quiet for 24h (so a subsequent first failure resets the
// escalation tier to 0). Hourly is fine: the failures table is small and the
// queries are pure DELETEs.
//
// TODO(max): What is auth_failures?
// TODO(max): What is auth_lockouts?
// TODO(max): cutoff resides inside queries? maybe factor out?
func authPruner(
	ctx context.Context,
	lgr *zap.Logger,
	queries *dbq.Queries,
	period time.Duration,
) error {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	if queries == nil {
		return errors.New("expected *dbq.Queries but got nil")
	}

	lgr = lgr.Named("auth-lockout-prune")

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		n, err := queries.PruneAuthFailures(ctx)
		if err != nil {
			lgr.Error("prune auth_failures failed", zap.Error(err))
		} else {
			lgr.Info("pruned auth_failures", zap.Int64("rows.count", n))
		}

		n, err = queries.PruneStaleAuthLockouts(ctx)
		if err != nil {
			lgr.Error("prune auth_lockouts failed", zap.Error(err))
		} else {
			lgr.Info("pruned auth_lockouts", zap.Int64("rows.count", n))
		}
	}
}

// Stuck-run sweeper — runs in 'running' status older than the absolute HTTP
// ceiling are presumed orphaned (airlock restart, agent crash mid- stream,
// network partition). Skip runs the dispatcher still tracks in memory: those
// will tear down naturally when the cancel context fires or the user clicks
// Cancel. Synthesize orphan tool_results so the next LLM turn doesn't 400 on
// unpaired tool_use, and publish a synthetic run.complete WS event so any live
// UI that was watching unblocks. If the agent's r.Complete eventually arrives,
// UpsertRunComplete is idempotent and the late truth overwrites — frontend
// re-paints.
func sweeper(
	ctx context.Context,
	lgr *zap.Logger,
	queries *dbq.Queries,
	dispatcher *trigger.Dispatcher,
	pubsub *realtime.PubSub,
	period time.Duration,
) error {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	const stuckCutoff = trigger.PromptHTTPCeiling + 30*time.Second

	if queries == nil {
		return errors.New("expected *dbq.Queries but got nil")
	}

	if dispatcher == nil {
		return errors.New("expected *trigger.Dispatcher but got nil")
	}

	if pubsub == nil {
		return errors.New("expected *realtime.PubSub but got nil")
	}

	lgr = lgr.Named("stuck-run-sweeper")

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		cutoff := pgtype.Timestamptz{
			Time:  time.Now().Add(-stuckCutoff),
			Valid: true,
		}

		stuck, err := queries.ListStuckRuns(ctx, cutoff)
		if err != nil {
			lgr.Error("list stuck runs", zap.Error(err))
			continue
		}

		if len(stuck) == 0 {
			continue
		}

		inFlight := make(map[uuid.UUID]struct{})
		for _, id := range dispatcher.InFlightIDs() {
			inFlight[id] = struct{}{}
		}

		for _, run := range stuck {
			runUUID, err := uuid.FromBytes(run.ID.Bytes[:])
			if err != nil {
				continue
			}

			if _, live := inFlight[runUUID]; live {
				continue
			}

			agentUUID, err := uuid.FromBytes(run.AgentID.Bytes[:])
			if err != nil {
				continue
			}

			// TODO(max): what happens here? weeeird
			api.SynthesizeOrphanToolResults(ctx, queries, runUUID, "timeout", lgr)

			queries.UpdateRunComplete(ctx, dbq.UpdateRunCompleteParams{
				ID:           run.ID,
				Status:       "error",
				ErrorMessage: "agent disconnected",
			})

			// TODO(max): again, what happens here? why it's called like this?
			api.PublishRunTerminal(ctx, pubsub, agentUUID, runUUID, "error", "agent disconnected")

			lgr.Warn(
				"stuck run reaped",
				zap.String("run_id", runUUID.String()),
				zap.String("agent_id", agentUUID.String()),
			)
		}
	}
}

// Attachment URL cache prune — drop rows that expired more than 24h ago.
// Stale rows aren't harmful (just unused), so a slow daily sweep is enough.
func cachePruner(
	ctx context.Context,
	lgr *zap.Logger,
	queries *dbq.Queries,
	period time.Duration,
) error {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	const stuckCutoff = trigger.PromptHTTPCeiling + 30*time.Second

	if queries == nil {
		return errors.New("expected *dbq.Queries but got nil")
	}

	lgr = lgr.Named("attachment-url-cache-prune")

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		n, err := queries.PruneExpiredAttachmentURLs(ctx)
		if err != nil {
			lgr.Error("prune attachment_url_cache failed", zap.Error(err))

			continue
		}

		lgr.Info("pruned attachment_url_cache", zap.Int64("rows.count", n))
	}
}
