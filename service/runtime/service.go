// Package runtime implements the backing operations used by hosted chat and the
// authenticated agent protocol. The capability broker authorizes hosted calls;
// this package never depends on HTTP handlers or accepts browser attribution.
package runtime

import (
	"context"

	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/networkpolicy"
	"github.com/airlockrun/airlock/oauth"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/airlock/service/capabilities"
	"github.com/airlockrun/airlock/service/chat"
	"github.com/airlockrun/airlock/storage"
	"go.uber.org/zap"
)

type UpgradeRunner interface {
	AcquireUpgradeLock(context.Context, string) error
	RunUpgrade(context.Context, builder.UpgradeInput)
}

type Config struct {
	DB                     *db.DB
	Encryptor              secrets.Store
	OAuthClient            *oauth.Client
	S3                     *storage.S3Client
	Files                  *agentstorage.Service
	Builder                UpgradeRunner
	PubSub                 *realtime.PubSub
	BridgeMgr              BridgePartsDeliverer
	HTTPNetwork            *networkpolicy.Policy
	Logger                 *zap.Logger
	LLMProxyURL            string
	PublicURL              string
	AgentBaseURL           func(slug string) string
	ForceInlineAttachments bool
}

type Service struct {
	db                     *db.DB
	encryptor              secrets.Store
	oauthClient            *oauth.Client
	s3                     *storage.S3Client
	files                  *agentstorage.Service
	builder                UpgradeRunner
	pubsub                 *realtime.PubSub
	bridgeMgr              BridgePartsDeliverer
	httpNetwork            *networkpolicy.Policy
	logger                 *zap.Logger
	llmProxyURL            string
	publicURL              string
	agentBaseURL           func(slug string) string
	forceInlineAttachments bool
}

func New(c Config) *Service {
	if c.PublicURL == "" || c.AgentBaseURL == nil {
		panic("runtime: public URL and app base URL resolver are required")
	}
	if c.DB == nil || c.Encryptor == nil || c.OAuthClient == nil || c.S3 == nil || c.Files == nil || c.Builder == nil || c.PubSub == nil || c.BridgeMgr == nil || c.HTTPNetwork == nil || c.Logger == nil {
		panic("runtime: database, secrets, OAuth, storage, files, builder, pubsub, bridge delivery, HTTP policy and logger are required")
	}
	return &Service{db: c.DB, encryptor: c.Encryptor, oauthClient: c.OAuthClient, s3: c.S3, files: c.Files, builder: c.Builder, pubsub: c.PubSub, bridgeMgr: c.BridgeMgr, httpNetwork: c.HTTPNetwork, logger: c.Logger, llmProxyURL: c.LLMProxyURL, publicURL: c.PublicURL, agentBaseURL: c.AgentBaseURL, forceInlineAttachments: c.ForceInlineAttachments}
}

var _ capabilities.Platform = (*Service)(nil)
var _ chat.Backend = (*Service)(nil)
