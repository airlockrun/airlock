// Package appruntime implements capabilities granted to a current app credential.
// App authority is confined to that app; it never certifies a human identity.
package appruntime

import (
	"context"
	"errors"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/networkpolicy"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service/jobs"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type ScheduleReconciler interface {
	ReconcileAgentTx(context.Context, pgx.Tx, uuid.UUID, int64, []wire.JobCronDef) error
	Wake()
}

var ErrUpstream = errors.New("upstream operation failed")

type AuthorizationRequired struct {
	Details map[string]string
}

func (e *AuthorizationRequired) Error() string { return e.Details["message"] }

type Config struct {
	DB           *db.DB
	Runtime      *runtimesvc.Service
	Encryptor    secrets.Store
	OAuthClient  *oauth.Client
	S3           *storage.S3Client
	PubSub       *realtime.PubSub
	BridgeMgr    runtimesvc.BridgePartsDeliverer
	Scheduler    ScheduleReconciler
	PublicURL    string
	AgentBaseURL func(string) string
	HTTPNetwork  *networkpolicy.Policy
	Logger       *zap.Logger
	Builder      runtimesvc.UpgradeRunner
}

type Service struct {
	db           *db.DB
	runtime      *runtimesvc.Service
	encryptor    secrets.Store
	oauthClient  *oauth.Client
	s3           *storage.S3Client
	pubsub       *realtime.PubSub
	bridgeMgr    runtimesvc.BridgePartsDeliverer
	scheduler    ScheduleReconciler
	publicURL    string
	agentBaseURL func(string) string
	httpNetwork  *networkpolicy.Policy
	logger       *zap.Logger
	builder      runtimesvc.UpgradeRunner
}

func New(c Config) *Service {
	if c.DB == nil || c.Runtime == nil || c.Encryptor == nil || c.OAuthClient == nil || c.S3 == nil || c.PubSub == nil || c.BridgeMgr == nil || c.Builder == nil || c.Scheduler == nil || c.PublicURL == "" || c.AgentBaseURL == nil || c.HTTPNetwork == nil || c.Logger == nil {
		panic("appruntime: app runtime dependencies are required")
	}
	return &Service{db: c.DB, runtime: c.Runtime, encryptor: c.Encryptor, oauthClient: c.OAuthClient, s3: c.S3, pubsub: c.PubSub, bridgeMgr: c.BridgeMgr, scheduler: c.Scheduler, publicURL: c.PublicURL, agentBaseURL: c.AgentBaseURL, httpNetwork: c.HTTPNetwork, logger: c.Logger, builder: c.Builder}
}

// admit reads only middleware-authenticated identity, never request selectors.
// A transaction retains the app lock through its protected mutations.
func (h *Service) admit(ctx context.Context, q *dbq.Queries) (uuid.UUID, error) {
	id := auth.AgentIDFromContext(ctx)
	if err := authz.Authorize(ctx, q, authz.TriggerPrincipal(), authz.AppRuntime, id); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func toPgUUID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil} }
func pgUUID(id pgtype.UUID) uuid.UUID   { return uuid.UUID(id.Bytes) }
func parseUUID(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, apperr.ErrInvalidInput
	}
	return id, nil
}

func jobManifestError(err error) error {
	switch {
	case errors.Is(err, jobs.ErrInvalidHandler), errors.Is(err, jobs.ErrInvalidJobCron), errors.Is(err, trigger.ErrInvalidJobCron):
		return apperr.Detail(apperr.ErrInvalidInput, "%s", err)
	case errors.Is(err, errStaleJobManifest), errors.Is(err, trigger.ErrStaleJobCrons):
		return apperr.Detail(apperr.ErrUnauthorized, "%s", err)
	case errors.Is(err, jobs.ErrContractConflict), errors.Is(err, errCandidateJobManifest):
		return apperr.Detail(apperr.ErrConflict, "%s", err)
	default:
		return err
	}
}
