package apitest_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	agentssvc "github.com/airlockrun/airlock/service/agents"
	grantssvc "github.com/airlockrun/airlock/service/grants"
	identitysvc "github.com/airlockrun/airlock/service/identity"
	managedbotssvc "github.com/airlockrun/airlock/service/managedbots"
	userssvc "github.com/airlockrun/airlock/service/users"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type bridgeStopper struct{}

func (bridgeStopper) TeardownBridge(uuid.UUID) {}
func (bridgeStopper) RemoveBridge(uuid.UUID)   {}

func agentService(h *apitest.Harness) *agentssvc.Service {
	return agentssvc.New(h.DB, h.BuildService, h.Dispatcher, h.FakeContainers, bridgeStopper{}, h.Secrets, zap.NewNop())
}

type telegramIdentityStub struct{}

func (telegramIdentityStub) GetChat(context.Context, string, string) (identitysvc.TelegramChatInfo, error) {
	return identitysvc.TelegramChatInfo{}, nil
}

func TestAgentDetailOmitsAdminCollectionsForMember(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "detail-owner", "user")
	member := apitest.CreateUser(t, h, "detail-member", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	apitest.AddAgentMember(t, h, agentID, member, "user")

	ctx := context.Background()
	statements := []string{
		`INSERT INTO agent_resource_needs (agent_id, type, slug, description, setup_instructions, expected_url, expected_scopes, spec) VALUES ($1, 'connection', 'private-connection', '', '', '', '', '{}')`,
		`INSERT INTO agent_webhooks (agent_id, path, verify_mode, verify_header, timeout_ms, description, secret) VALUES ($1, 'private-webhook', 'none', '', 1000, '', '')`,
		`INSERT INTO agent_schedule_handlers (agent_id, slug, kind, recurrence, timeout_ms, description) VALUES ($1, 'private-cron', 'cron', '* * * * *', 1000, '')`,
		`INSERT INTO agent_routes (agent_id, path, method, access, description) VALUES ($1, '/private', 'GET', 'admin', '')`,
	}
	for _, statement := range statements {
		if _, err := h.DB.Pool().Exec(ctx, statement, agentID); err != nil {
			t.Fatalf("seed admin collection: %v", err)
		}
	}

	svc := agentService(h)
	ownerDetail, err := svc.Get(ctx, authz.UserPrincipal(owner, auth.RoleUser), agentID)
	if err != nil {
		t.Fatalf("owner Get: %v", err)
	}
	if len(ownerDetail.Connections) != 1 || len(ownerDetail.Webhooks) != 1 || len(ownerDetail.Schedules) != 1 || len(ownerDetail.Routes) != 1 {
		t.Fatalf("owner collections = connections:%d webhooks:%d schedules:%d routes:%d, want one each",
			len(ownerDetail.Connections), len(ownerDetail.Webhooks), len(ownerDetail.Schedules), len(ownerDetail.Routes))
	}
	memberDetail, err := svc.Get(ctx, authz.UserPrincipal(member, auth.RoleUser), agentID)
	if err != nil {
		t.Fatalf("member Get: %v", err)
	}
	if len(memberDetail.Connections) != 0 || len(memberDetail.Webhooks) != 0 || len(memberDetail.Schedules) != 0 || len(memberDetail.Routes) != 0 {
		t.Fatalf("member received admin collections: connections:%d webhooks:%d schedules:%d routes:%d",
			len(memberDetail.Connections), len(memberDetail.Webhooks), len(memberDetail.Schedules), len(memberDetail.Routes))
	}
}

func TestAgentCreateAndCloneRejectUngrantedModels(t *testing.T) {
	h := apitest.Setup(t)
	manager := apitest.CreateUser(t, h, "model-manager", "manager")
	principal := authz.UserPrincipal(manager, auth.RoleManager)
	providerID := uuid.New()
	q := dbq.New(h.DB.Pool())
	if _, err := q.CreateProvider(context.Background(), dbq.CreateProviderParams{
		ID: pgUUID(providerID), CatalogID: "openai", Slug: "blocked-provider", DisplayName: "Blocked", ApiKey: "k", BaseUrl: "", IsEnabled: true,
	}); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}

	create := agentssvc.CreateRequest{
		Name: "Denied create", Slug: "denied-create", BuildProviderID: providerID.String(), BuildModel: "blocked-model", SkipInitialBuild: true,
	}
	svc := agentService(h)
	if _, err := svc.Create(context.Background(), principal, create); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("create with ungranted model error = %v, want forbidden", err)
	}

	sourceID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: manager})
	if _, err := h.DB.Pool().Exec(context.Background(),
		`UPDATE agents SET source_ref='source', build_provider_id=$2, build_model='blocked-model' WHERE id=$1`, sourceID, providerID); err != nil {
		t.Fatalf("set source model: %v", err)
	}
	clone := agentssvc.CloneRequest{Name: "Denied clone", Slug: "denied-clone"}
	if _, err := svc.Clone(context.Background(), principal, sourceID, clone); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("clone with ungranted model error = %v, want forbidden", err)
	}
}

func TestManagedBotSessionRequiresTargetAgentAdmin(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "bot-owner", "user")
	manager := apitest.CreateUser(t, h, "bot-manager", "manager")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	apitest.AddAgentMember(t, h, agentID, manager, "user")
	svc := managedbotssvc.New(managedbotssvc.Deps{
		DB: h.DB,
		ManagerBridgeUsername: func(context.Context) (string, error) {
			return "", errors.New("manager callback must not be reached")
		},
		Logger: zap.NewNop(),
	})
	_, err := svc.CreateSession(context.Background(), authz.UserPrincipal(manager, auth.RoleManager), managedbotssvc.CreateSessionRequest{
		AgentID: agentID, SuggestedName: "Denied bot",
	})
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("member managed-bot session error = %v, want forbidden", err)
	}
}

func TestResourceGrantRevokeBindsRouteResource(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "grant-owner", "user")
	resourceA, resourceB, grantB := uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	for _, id := range []uuid.UUID{resourceA, resourceB} {
		if _, err := h.DB.Pool().Exec(ctx,
			`INSERT INTO git_credentials (id, user_id, type, name, token_ref, github_install_id) VALUES ($1, $2, 'token', $3, 'ref', '')`, id, owner, id.String()); err != nil {
			t.Fatalf("insert git credential: %v", err)
		}
	}
	if _, err := h.DB.Pool().Exec(ctx,
		`INSERT INTO resource_grants (id, git_credential_id, grantee_id, capabilities) VALUES ($1, $2, $3, ARRAY['view'])`, grantB, resourceB, authz.GroupUser); err != nil {
		t.Fatalf("insert resource grant: %v", err)
	}
	svc := grantssvc.New(h.DB, zap.NewNop())
	err := svc.RevokeResourceGrant(ctx, authz.UserPrincipal(owner, auth.RoleUser), "git_credential", resourceA, grantB)
	if !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("cross-resource revoke error = %v, want not found", err)
	}
	var exists bool
	if err := h.DB.Pool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resource_grants WHERE id=$1)`, grantB).Scan(&exists); err != nil {
		t.Fatalf("check resource grant: %v", err)
	}
	if !exists {
		t.Fatal("cross-resource revoke deleted the grant")
	}
}

func TestIdentityLinkChallengeIsOneTimeAndCannotTransfer(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "identity-owner", "user")
	other := apitest.CreateUser(t, h, "identity-other", "user")
	ctx := context.Background()
	bridgeID := uuid.New()
	secret, err := h.Secrets.Put(ctx, "bridge/"+bridgeID.String()+"/bot_token", "token")
	if err != nil {
		t.Fatalf("encrypt bridge token: %v", err)
	}
	if _, err := h.DB.Pool().Exec(ctx,
		`INSERT INTO bridges (id, type, name, bot_token_ref, bot_username, status, is_system, config, settings) VALUES ($1, 'telegram', 'link', $2, 'link_bot', 'active', false, '{}', '{}')`, bridgeID, secret); err != nil {
		t.Fatalf("insert bridge: %v", err)
	}
	svc := identitysvc.New(h.DB, h.Secrets, telegramIdentityStub{}, zap.NewNop())
	const uid = "external-user"
	preview := func(user uuid.UUID, challenge string) {
		t.Helper()
		_, err := svc.Preview(ctx, authz.UserPrincipal(user, auth.RoleUser), identitysvc.PreviewInput{
			Platform: "telegram", BridgeID: bridgeID, UID: uid,
			ChallengeHash: challenge, ExpiresAt: time.Now().Add(time.Minute),
		})
		if err != nil {
			t.Fatalf("Preview: %v", err)
		}
	}
	link := func(user uuid.UUID, challenge string) error {
		return svc.Link(ctx, authz.UserPrincipal(user, auth.RoleUser), identitysvc.LinkInput{
			Platform: "telegram", BridgeID: bridgeID, UID: uid, ChallengeHash: challenge,
		})
	}
	preview(owner, "first-challenge")
	if err := link(owner, "first-challenge"); err != nil {
		t.Fatalf("first Link: %v", err)
	}
	if err := link(owner, "first-challenge"); !errors.Is(err, service.ErrInvalidInput) {
		t.Fatalf("replayed Link error = %v, want invalid input", err)
	}
	preview(other, "transfer-challenge")
	if err := link(other, "transfer-challenge"); !errors.Is(err, service.ErrConflict) {
		t.Fatalf("transfer Link error = %v, want conflict", err)
	}
	identity, err := dbq.New(h.DB.Pool()).GetPlatformIdentity(ctx, dbq.GetPlatformIdentityParams{
		Platform: "telegram", PlatformUserID: uid,
	})
	if err != nil {
		t.Fatalf("GetPlatformIdentity: %v", err)
	}
	if got := uuid.UUID(identity.UserID.Bytes); got != owner {
		t.Fatalf("identity owner = %s, want %s", got, owner)
	}
}

func TestConcurrentAdminMutationsKeepOneAdmin(t *testing.T) {
	h := apitest.Setup(t)
	adminA := apitest.CreateUser(t, h, "admin-a", "admin")
	adminB := apitest.CreateUser(t, h, "admin-b", "admin")
	svc := userssvc.New(h.DB, nil, zap.NewNop())
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		errs <- svc.Delete(context.Background(), authz.UserPrincipal(adminA, auth.RoleAdmin), adminB)
	}()
	go func() {
		defer wg.Done()
		<-start
		errs <- svc.UpdateRole(context.Background(), authz.UserPrincipal(adminB, auth.RoleAdmin), adminA, "user")
	}()
	close(start)
	wg.Wait()
	close(errs)

	var succeeded, rejected int
	for err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, userssvc.ErrLastAdmin):
			rejected++
		default:
			t.Fatalf("admin mutation returned unexpected error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("admin mutations: succeeded=%d rejected=%d, want 1 each", succeeded, rejected)
	}
	count, err := dbq.New(h.DB.Pool()).CountTenantAdmins(context.Background())
	if err != nil {
		t.Fatalf("CountTenantAdmins: %v", err)
	}
	if count != 1 {
		t.Fatalf("admin count = %d, want 1", count)
	}
}
