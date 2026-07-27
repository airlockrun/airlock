// Package grants owns model entitlements ((provider, model) -> principal).
package grants

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type Service struct {
	db     *db.DB
	logger *zap.Logger
}

func New(database *db.DB, logger *zap.Logger) *Service {
	if database == nil || logger == nil {
		panic("grants: nil dependency")
	}
	return &Service{db: database, logger: logger}
}

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// ModelGrant is a (provider, model) entitlement granted to a principal.
type ModelGrant struct {
	ID           uuid.UUID
	ProviderID   uuid.UUID
	CatalogID    string
	ProviderSlug string
	Model        string
	GranteeID    uuid.UUID
}

// GrantModel entitles a grantee to assign a (provider, model). Tenant-admin only.
func (s *Service) GrantModel(ctx context.Context, p authz.Principal, providerID uuid.UUID, model string, granteeID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantModelGrantManage, uuid.Nil); err != nil {
		return err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := q.WithTx(tx)
	provider, err := qtx.GetProviderByIDForUpdate(ctx, pg(providerID))
	if err != nil {
		return service.ErrNotFound
	}
	if !provider.IsEnabled {
		return service.Detail(service.ErrInvalidInput, "provider %q (%s) is disabled", provider.CatalogID, provider.Slug)
	}
	if model == "" {
		return service.Detail(service.ErrInvalidInput, "model is required")
	}
	if provider.CatalogID == "openai-compatible" {
		if _, err := qtx.GetProviderModel(ctx, dbq.GetProviderModelParams{ConfiguredProviderID: pg(providerID), ModelID: model}); err != nil {
			return service.Detail(service.ErrInvalidInput, "model %q is not confirmed for provider %q", model, provider.Slug)
		}
	}
	if _, err := qtx.CreateModelGrant(ctx, dbq.CreateModelGrantParams{CatalogID: pg(providerID), Model: model, GranteeID: pg(granteeID)}); err != nil {
		s.logger.Error("create model grant", zap.Error(err))
		return err
	}
	return tx.Commit(ctx)
}

// RevokeModelGrant removes a model entitlement (disables the model). Tenant-
// admin only. After revoking, any agent that pinned this (provider, model) as a
// capability override or slot assignment is reset back to the workspace default
// — unless the model is itself a configured system default, in which case it
// stays usable and the overrides are left untouched. A discovery race retries
// before writes; the mutating attempt runs in one transaction.
func (s *Service) RevokeModelGrant(ctx context.Context, p authz.Principal, grantID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantModelGrantManage, uuid.Nil); err != nil {
		return err
	}
	grant, err := q.GetModelGrant(ctx, pg(grantID))
	if err != nil {
		return service.ErrNotFound
	}
	for {
		retry, err := s.revokeModelGrant(ctx, grantID, grant.CatalogID, grant.Model)
		if err != nil {
			return err
		}
		if !retry {
			return nil
		}
	}
}

func (s *Service) revokeModelGrant(ctx context.Context, grantID uuid.UUID, providerID pgtype.UUID, model string) (bool, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	qtx := dbq.New(s.db.Pool()).WithTx(tx)
	params := dbq.ListAgentIDsUsingModelParams{CatalogID: providerID, Model: model}
	affected, err := qtx.ListAgentIDsUsingModel(ctx, params)
	if err != nil {
		return false, err
	}
	if _, err := qtx.LockAgentsByID(ctx, affected); err != nil {
		return false, err
	}
	if _, err := qtx.GetProviderByIDForUpdate(ctx, providerID); err != nil {
		return false, err
	}

	// An assignment to this pair can commit between discovery and the provider
	// lock only if its transaction acquired the provider first. Retry without
	// writing so every row cleared below was locked before the provider.
	stable, err := qtx.ListAgentIDsUsingModel(ctx, params)
	if err != nil {
		return false, err
	}
	locked := make(map[[16]byte]struct{}, len(affected))
	for _, id := range affected {
		locked[id.Bytes] = struct{}{}
	}
	for _, id := range stable {
		if _, ok := locked[id.Bytes]; !ok {
			return true, nil
		}
	}
	if err := qtx.RevokeModelGrant(ctx, pg(grantID)); err != nil {
		return false, err
	}
	isDefault, err := qtx.IsSystemDefaultModel(ctx, dbq.IsSystemDefaultModelParams{CatalogID: providerID, Model: model})
	if err != nil {
		return false, err
	}
	if !isDefault {
		if err := clearAgentModelRefs(ctx, qtx, providerID, model); err != nil {
			s.logger.Error("reset agent overrides after model revoke", zap.Error(err))
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return false, nil
}

// ModelUsage reports how a (provider, model) is currently configured so the UI
// can confirm before disabling it. Tenant-admin only.
func (s *Service) ModelUsage(ctx context.Context, p authz.Principal, providerID uuid.UUID, model string) (agentCount int, isSystemDefault bool, err error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantModelGrantManage, uuid.Nil); err != nil {
		return 0, false, err
	}
	cnt, err := q.CountAgentsUsingModel(ctx, dbq.CountAgentsUsingModelParams{CatalogID: pg(providerID), Model: model})
	if err != nil {
		return 0, false, err
	}
	def, err := q.IsSystemDefaultModel(ctx, dbq.IsSystemDefaultModelParams{CatalogID: pg(providerID), Model: model})
	if err != nil {
		return 0, false, err
	}
	return int(cnt), def, nil
}

// clearAgentModelRefs resets every agent capability override and declared
// model-slot assignment that pins (providerID, model) back to inherit (NULL
// provider + ” model → the workspace default). One statement per capability
// keeps the query generator's named params unambiguous.
func clearAgentModelRefs(ctx context.Context, q *dbq.Queries, providerID pgtype.UUID, model string) error {
	if _, err := q.ClearAgentBuildModel(ctx, dbq.ClearAgentBuildModelParams{CatalogID: providerID, Model: model}); err != nil {
		return err
	}
	if _, err := q.ClearAgentExecModel(ctx, dbq.ClearAgentExecModelParams{CatalogID: providerID, Model: model}); err != nil {
		return err
	}
	if _, err := q.ClearAgentSttModel(ctx, dbq.ClearAgentSttModelParams{CatalogID: providerID, Model: model}); err != nil {
		return err
	}
	if _, err := q.ClearAgentVisionModel(ctx, dbq.ClearAgentVisionModelParams{CatalogID: providerID, Model: model}); err != nil {
		return err
	}
	if _, err := q.ClearAgentTtsModel(ctx, dbq.ClearAgentTtsModelParams{CatalogID: providerID, Model: model}); err != nil {
		return err
	}
	if _, err := q.ClearAgentImageGenModel(ctx, dbq.ClearAgentImageGenModelParams{CatalogID: providerID, Model: model}); err != nil {
		return err
	}
	if _, err := q.ClearAgentEmbeddingModel(ctx, dbq.ClearAgentEmbeddingModelParams{CatalogID: providerID, Model: model}); err != nil {
		return err
	}
	if _, err := q.ClearAgentSearchModel(ctx, dbq.ClearAgentSearchModelParams{CatalogID: providerID, Model: model}); err != nil {
		return err
	}
	if _, err := q.ClearAgentModelSlotsForModel(ctx, dbq.ClearAgentModelSlotsForModelParams{CatalogID: providerID, Model: model}); err != nil {
		return err
	}
	return nil
}

// ListModelGrants returns every model entitlement. Tenant-admin only.
func (s *Service) ListModelGrants(ctx context.Context, p authz.Principal) ([]ModelGrant, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantModelGrantManage, uuid.Nil); err != nil {
		return nil, err
	}
	rows, err := q.ListModelGrants(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ModelGrant, len(rows))
	for i, r := range rows {
		out[i] = ModelGrant{
			ID:           uuid.UUID(r.ID.Bytes),
			ProviderID:   uuid.UUID(r.CatalogID.Bytes),
			CatalogID:    r.ProviderCatalog,
			ProviderSlug: r.ProviderSlug,
			Model:        r.Model,
			GranteeID:    uuid.UUID(r.GranteeID.Bytes),
		}
	}
	return out, nil
}
