package agentapi

import (
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/networkpolicy"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service/agentruns"
	agentstoragesvc "github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/airlock/service/appruntime"
	connectordirectoriessvc "github.com/airlockrun/airlock/service/connectordirectories"
	connectorjobssvc "github.com/airlockrun/airlock/service/connectorjobs"
	connectororchestrationsvc "github.com/airlockrun/airlock/service/connectororchestration"
	jobssvc "github.com/airlockrun/airlock/service/jobs"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/airlock/storage"
	"go.uber.org/zap"
)

type Handler struct {
	agentRuns              *agentruns.Service
	runtime                *runtimesvc.Service
	db                     *db.DB
	encryptor              secrets.Store
	oauthClient            *oauth.Client
	s3                     *storage.S3Client
	files                  *agentstoragesvc.Service
	jobs                   *jobssvc.Service
	connectorJobs          *connectorjobssvc.Service
	connectorDirectories   *connectordirectoriessvc.Service
	connectorOrchestration *connectororchestrationsvc.Service
	builder                runtimesvc.UpgradeRunner
	pubsub                 *realtime.PubSub
	bridgeMgr              runtimesvc.BridgePartsDeliverer // for output()/topic bridge delivery
	scheduler              appruntime.ScheduleReconciler
	publicURL              string
	agentBaseURL           func(slug string) string // {scheme}://{slug}.{domain}[:port] — from config.Config (single source)
	jwtSecret              string                   // validates external MCP user and OAuth credentials
	httpNetwork            *networkpolicy.Policy
	logger                 *zap.Logger
}

// Config bundles the dependencies New requires. Mirrors the struct
// fields of Handler one-for-one; api/router.go's RouterConfig
// translates its own merged config into this on wire-up.
type Config struct {
	AgentRuns              *agentruns.Service
	Runtime                *runtimesvc.Service
	DB                     *db.DB
	Encryptor              secrets.Store
	OAuthClient            *oauth.Client
	S3                     *storage.S3Client
	Files                  *agentstoragesvc.Service
	Jobs                   *jobssvc.Service
	ConnectorJobs          *connectorjobssvc.Service
	ConnectorDirectories   *connectordirectoriessvc.Service
	ConnectorOrchestration *connectororchestrationsvc.Service
	Builder                *builder.BuildService
	PubSub                 *realtime.PubSub
	BridgeMgr              runtimesvc.BridgePartsDeliverer
	Scheduler              appruntime.ScheduleReconciler
	PublicURL              string
	AgentBaseURL           func(slug string) string
	JWTSecret              string
	HTTPNetwork            *networkpolicy.Policy
	Logger                 *zap.Logger
}

// New constructs the agent-internal HTTP surface. Fail-loud on nil
// deps — every required field is mandatory (airlock fail-loud rule).
func New(c Config) *Handler {
	if c.AgentRuns == nil {
		panic("agentapi: agent runs service is required")
	}
	if c.Runtime == nil {
		panic("agentapi: runtime service is required")
	}
	if c.DB == nil {
		panic("agentapi: db is required")
	}
	if c.Encryptor == nil {
		panic("agentapi: encryptor is required")
	}
	if c.PubSub == nil {
		panic("agentapi: pubsub is required")
	}
	if c.Builder == nil || c.OAuthClient == nil || c.S3 == nil || c.BridgeMgr == nil || c.AgentBaseURL == nil {
		panic("agentapi: app runtime dependencies are required")
	}
	if c.Logger == nil {
		panic("agentapi: logger is required")
	}
	if c.HTTPNetwork == nil {
		panic("agentapi: HTTP network policy is required")
	}
	if c.Files == nil {
		panic("agentapi: file service is required")
	}
	if c.Jobs == nil {
		panic("agentapi: jobs service is required")
	}
	if c.ConnectorJobs == nil {
		panic("agentapi: connector jobs service is required")
	}
	if c.ConnectorDirectories == nil {
		panic("agentapi: connector directories service is required")
	}
	if c.ConnectorOrchestration == nil {
		panic("agentapi: connector orchestration service is required")
	}
	if c.Scheduler == nil {
		panic("agentapi: scheduler is required")
	}
	return &Handler{
		agentRuns:              c.AgentRuns,
		runtime:                c.Runtime,
		db:                     c.DB,
		encryptor:              c.Encryptor,
		oauthClient:            c.OAuthClient,
		s3:                     c.S3,
		files:                  c.Files,
		jobs:                   c.Jobs,
		connectorJobs:          c.ConnectorJobs,
		connectorDirectories:   c.ConnectorDirectories,
		connectorOrchestration: c.ConnectorOrchestration,
		builder:                c.Builder,
		pubsub:                 c.PubSub,
		bridgeMgr:              c.BridgeMgr,
		scheduler:              c.Scheduler,
		publicURL:              c.PublicURL,
		agentBaseURL:           c.AgentBaseURL,
		jwtSecret:              c.JWTSecret,
		httpNetwork:            c.HTTPNetwork,
		logger:                 c.Logger,
	}
}
