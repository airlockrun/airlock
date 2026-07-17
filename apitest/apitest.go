package apitest

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/airlock/api"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbtest"
	"github.com/airlockrun/airlock/networkpolicy"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"go.uber.org/zap/zaptest"
)

// JWTSecret is the shared HS256 secret used by every test in the
// package. Stable across runs so test JWTs can be hand-crafted if
// needed.
const JWTSecret = "apitest-jwt-secret-stable-across-runs"

// EncryptionKey is the 32-byte AES-256-GCM key for secrets.NewLocal,
// hex-encoded. Stable to match real config decoding.
const EncryptionKey = "0001020304050607080910111213141516171819202122232425262728293031"

var (
	pkgOnce    sync.Once
	pkgState   *packageState
	pkgInitErr error
)

type packageState struct {
	dsn      string
	dbReset  func() error
	s3Params S3Params
	teardown func()
}

// PackageMain wires dbtest + s3test once per test binary and runs
// m.Run. The test package's TestMain should be:
//
//	func TestMain(m *testing.M) { os.Exit(apitest.PackageMain(m)) }
//
// If Docker is unreachable for either Postgres or MinIO, PackageMain
// returns the m.Run exit code with no harness state — tests that call
// Setup will skip individually.
func PackageMain(m interface{ Run() int }) int {
	ctx := context.Background()
	pkgOnce.Do(func() {
		dsn, reset, releaseDB, dbOK := dbtest.Setup(ctx, db.RunMigrations)
		if !dbOK {
			pkgInitErr = errors.New("apitest: no postgres available (docker unreachable)")
			return
		}
		s3, releaseS3, s3OK := setupS3(ctx)
		if !s3OK {
			releaseDB()
			pkgInitErr = errors.New("apitest: no s3/minio available (docker unreachable)")
			return
		}
		pkgState = &packageState{
			dsn:      dsn,
			dbReset:  reset,
			s3Params: s3,
			teardown: func() { releaseS3(); releaseDB() },
		}
	})
	code := m.Run()
	if pkgState != nil {
		pkgState.teardown()
	}
	return code
}

// Available reports whether PackageMain succeeded — i.e. tests can
// call Setup. Useful in skip helpers.
func Available() bool { return pkgState != nil }

// SkipIfUnavailable skips the test when the harness couldn't boot
// (no Docker / no external services). Matches the dbtest skip
// contract.
func SkipIfUnavailable(t *testing.T) {
	t.Helper()
	if pkgState == nil {
		t.Skipf("apitest unavailable: %v", pkgInitErr)
	}
}

// Harness is the per-test toolbox. Build it via Setup; teardown is
// registered with t.Cleanup automatically.
//
// The Server field is an httptest.NewServer wrapping the real
// api.NewRouter — middleware chain, CORS, auth, the lot. Tests drive
// HTTP requests against Server.URL.
//
// FakeContainers lets tests register canned upstream handlers per
// agent before driving requests that would reach the dispatcher.
type Harness struct {
	T              *testing.T
	Server         *httptest.Server
	DB             *db.DB
	S3             *storage.S3Client
	Secrets        secrets.Store
	FakeContainers *FakeContainerManager
	Hub            *realtime.Hub
	PubSub         *realtime.PubSub
	Dispatcher     *trigger.Dispatcher
	BuildService   *builder.BuildService
	JWTSecret      string
}

// Setup builds a fresh harness. It restores the DB to the
// post-migration snapshot first so per-test state is isolated.
//
// The order is:
//  1. SkipIfUnavailable — bail cleanly if no Docker/MinIO/PG.
//  2. resetDB — DROP+CREATE WITH TEMPLATE.
//  3. open pool, build S3, build all router deps.
//  4. NewRouter, NewServer, register t.Cleanup.
func Setup(t *testing.T) *Harness {
	t.Helper()
	SkipIfUnavailable(t)

	if err := pkgState.dbReset(); err != nil {
		t.Fatalf("apitest: db reset: %v", err)
	}

	ctx := context.Background()
	database := db.New(ctx, pkgState.dsn)

	logger := zaptest.NewLogger(t).Named("apitest")

	cfg := &config.Config{
		DatabaseURL:    pkgState.dsn,
		JWTSecret:      JWTSecret,
		S3URL:          pkgState.s3Params.Endpoint,
		S3AccessKey:    pkgState.s3Params.AccessKey,
		S3SecretKey:    pkgState.s3Params.SecretKey,
		S3Bucket:       pkgState.s3Params.Bucket,
		S3Region:       pkgState.s3Params.Region,
		PublicURL:      "http://apitest.local",
		AgentScheme:    "http",
		AgentDomain:    "apitest.local",
		AgentReposPath: t.TempDir(),
		EncryptionKey:  EncryptionKey,
	}

	s3Client := storage.NewS3Client(cfg)
	if err := s3Client.EnsureBucket(ctx); err != nil {
		database.Close()
		t.Fatalf("apitest: ensure bucket: %v", err)
	}

	encKey := mustHex(EncryptionKey)
	secretStore := secrets.NewLocal(crypto.New(encKey))

	fakeContainers := NewFakeContainerManager()
	buildSvc := builder.New(cfg, database, fakeContainers, secretStore, logger.Named("builder"))
	hub := realtime.NewHub(logger.Named("hub"))
	pubsub := realtime.NewPubSub(hub, logger.Named("pubsub"))
	buildSvc.SetEventPublisher(realtime.NewBuildEventPublisher(pubsub, hub))

	wsHandler := realtime.NewHandler(database, hub, pubsub, logger.Named("ws-handler"))
	dispatcher := trigger.NewDispatcher(cfg, database, fakeContainers, secretStore, logger.Named("dispatcher"))
	transcription := trigger.NewTranscriptionResolver(database, secretStore)
	prompter := trigger.NewPromptProxy(dispatcher, database, s3Client, transcription, logger.Named("prompt-proxy"))
	telegram := trigger.NewTelegramDriver(logger.Named("telegram"))
	bridgeMgr := trigger.NewBridgeManager(
		map[string]trigger.BridgeDriver{"telegram": telegram},
		prompter, database, secretStore, cfg.JWTSecret, cfg.PublicURL, cfg.AgentBaseURL,
		logger.Named("bridges"),
	)
	scheduler := trigger.NewScheduler(dispatcher, database, logger.Named("scheduler"))

	httpNetwork := networkpolicy.New(cfg.AgentHTTPPrivateCIDRs, true)
	router := api.NewRouter(api.RouterConfig{
		DB:             database,
		JWTSecret:      cfg.JWTSecret,
		PublicURL:      cfg.PublicURL,
		OAuthClient:    oauth.NewClient(httpNetwork.Client(30*time.Second), true),
		TelegramDriver: telegram,
		Secrets:        secretStore,
		S3Client:       s3Client,
		BuildService:   buildSvc,
		Dispatcher:     dispatcher,
		Scheduler:      scheduler,
		BridgeManager:  bridgeMgr,
		Containers:     fakeContainers,
		PromptProxy:    prompter,
		Hub:            hub,
		PubSub:         pubsub,
		Handler:        wsHandler,
		AgentDomain:    cfg.AgentDomain,
		AgentBaseURL:   cfg.AgentBaseURL, // method value
		HTTPNetwork:    httpNetwork,
		RealIP:         api.ParseRealIPConfig("", 1, "apitest-reverse-proxy-secret-32-bytes"),
		Logger:         logger,
	})

	srv := httptest.NewServer(router)

	t.Cleanup(func() {
		// CloseClientConnections before Close: srv.Close() blocks until
		// active connections drain, and our integration tests can leave
		// handlers wedged (e.g. a fake upstream parked on r.Context() that
		// never fires under the test's failure mode). Force-closing
		// connections first unblocks those handlers in milliseconds rather
		// than waiting for the `go test -timeout` to SIGQUIT the whole
		// binary 10 minutes later. Same reason FakeContainerManager.Close
		// nukes its per-agent servers the same way.
		srv.CloseClientConnections()
		srv.Close()
		fakeContainers.Close()
		pubsub.Close()
		database.Close()
	})

	return &Harness{
		T:              t,
		Server:         srv,
		DB:             database,
		S3:             s3Client,
		Secrets:        secretStore,
		FakeContainers: fakeContainers,
		Hub:            hub,
		PubSub:         pubsub,
		Dispatcher:     dispatcher,
		BuildService:   buildSvc,
		JWTSecret:      cfg.JWTSecret,
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("apitest: bad hex constant: " + err.Error())
	}
	return b
}
