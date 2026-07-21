// Package grants owns management-plane authorization grants: capability grants
// on user-owned resources (connection / mcp_server / exec_endpoint /
// git_credential) and model entitlements ((provider, model) -> principal).
//
// Resource-grant management is gated by the manage capability on the resource
// itself (owner, or a manage grant) rather than a tenant/agent action — sharing
// is the resource owner's call. Model-grant management is tenant-admin only.
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

// ResourceGrant is a capability grant on a resource.
type ResourceGrant struct {
	ID           uuid.UUID
	GranteeID    uuid.UUID
	Capabilities []string
}

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func validCaps(caps []string) bool {
	if len(caps) == 0 {
		return false
	}
	for _, c := range caps {
		if c != authz.CapView && c != authz.CapBind && c != authz.CapManage {
			return false
		}
	}
	return true
}

// GrantResource grants capabilities on a resource to a grantee. The caller must
// hold the manage capability on the resource.
func (s *Service) GrantResource(ctx context.Context, p authz.Principal, resourceType string, resourceID, granteeID uuid.UUID, caps []string) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.LockResource(ctx, q, resourceType, resourceID); err != nil {
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, resourceType, resourceID); err != nil {
		return err
	}
	if !validCaps(caps) {
		return service.Detail(service.ErrInvalidInput, "capabilities must be a non-empty subset of view/bind/manage")
	}
	err = nil
	switch resourceType {
	case "connection":
		_, err = q.CreateConnectionGrant(ctx, dbq.CreateConnectionGrantParams{ConnectionID: pg(resourceID), GranteeID: pg(granteeID), Capabilities: caps})
	case "mcp_server":
		_, err = q.CreateMCPServerGrant(ctx, dbq.CreateMCPServerGrantParams{McpServerID: pg(resourceID), GranteeID: pg(granteeID), Capabilities: caps})
	case "exec_endpoint":
		_, err = q.CreateExecEndpointGrant(ctx, dbq.CreateExecEndpointGrantParams{ExecEndpointID: pg(resourceID), GranteeID: pg(granteeID), Capabilities: caps})
	case "git_credential":
		_, err = q.CreateGitCredentialGrant(ctx, dbq.CreateGitCredentialGrantParams{GitCredentialID: pg(resourceID), GranteeID: pg(granteeID), Capabilities: caps})
	}
	if err != nil {
		s.logger.Error("create resource grant", zap.Error(err))
		return err
	}
	return tx.Commit(ctx)
}

// RevokeResourceGrant deletes a grant by id. The caller must hold manage on the
// resource the grant belongs to.
func (s *Service) RevokeResourceGrant(ctx context.Context, p authz.Principal, resourceType string, resourceID, grantID uuid.UUID) error {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := authz.LockResource(ctx, q, resourceType, resourceID); err != nil {
		return err
	}
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, resourceType, resourceID); err != nil {
		return err
	}
	deleted, err := q.RevokeResourceGrant(ctx, dbq.RevokeResourceGrantParams{
		ID:           pg(grantID),
		ResourceType: resourceType,
		ResourceID:   pg(resourceID),
	})
	if err != nil {
		return err
	}
	if deleted == 0 {
		return service.ErrNotFound
	}
	return tx.Commit(ctx)
}

// ListResourceGrants returns a resource's grants. Sharing metadata is visible
// only to callers who can manage that resource.
func (s *Service) ListResourceGrants(ctx context.Context, p authz.Principal, resourceType string, resourceID uuid.UUID) ([]ResourceGrant, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.AuthorizeResource(ctx, q, p, authz.ResourceManage, resourceType, resourceID); err != nil {
		return nil, err
	}
	var out []ResourceGrant
	switch resourceType {
	case "connection":
		rows, err := q.ListConnectionGrants(ctx, pg(resourceID))
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out = append(out, ResourceGrant{ID: uuid.UUID(row.ID.Bytes), GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
		}
	case "mcp_server":
		rows, err := q.ListMCPServerGrants(ctx, pg(resourceID))
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out = append(out, ResourceGrant{ID: uuid.UUID(row.ID.Bytes), GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
		}
	case "exec_endpoint":
		rows, err := q.ListExecEndpointGrants(ctx, pg(resourceID))
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out = append(out, ResourceGrant{ID: uuid.UUID(row.ID.Bytes), GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
		}
	case "git_credential":
		rows, err := q.ListGitCredentialGrants(ctx, pg(resourceID))
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out = append(out, ResourceGrant{ID: uuid.UUID(row.ID.Bytes), GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
		}
	}
	return out, nil
}

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
	if _, err := q.CreateModelGrant(ctx, dbq.CreateModelGrantParams{CatalogID: pg(providerID), Model: model, GranteeID: pg(granteeID)}); err != nil {
		s.logger.Error("create model grant", zap.Error(err))
		return err
	}
	return nil
}

// RevokeModelGrant removes a model entitlement (disables the model). Tenant-
// admin only. After revoking, any agent that pinned this (provider, model) as a
// capability override or slot assignment is reset back to the workspace default
// — unless the model is itself a configured system default, in which case it
// stays usable and the overrides are left untouched. Runs in one transaction.
func (s *Service) RevokeModelGrant(ctx context.Context, p authz.Principal, grantID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantModelGrantManage, uuid.Nil); err != nil {
		return err
	}
	grant, err := q.GetModelGrant(ctx, pg(grantID))
	if err != nil {
		return service.ErrNotFound
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := q.WithTx(tx)
	if err := qtx.RevokeModelGrant(ctx, pg(grantID)); err != nil {
		return err
	}
	isDefault, err := qtx.IsSystemDefaultModel(ctx, dbq.IsSystemDefaultModelParams{CatalogID: grant.CatalogID, Model: grant.Model})
	if err != nil {
		return err
	}
	if !isDefault {
		if err := clearAgentModelRefs(ctx, qtx, grant.CatalogID, grant.Model); err != nil {
			s.logger.Error("reset agent overrides after model revoke", zap.Error(err))
			return err
		}
	}
	return tx.Commit(ctx)
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
