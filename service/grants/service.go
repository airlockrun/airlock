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

// ownerAndGrants returns the resource's owner principal and its existing grants
// for the capability check. resourceType is connection|mcp_server|
// exec_endpoint|git_credential.
func (s *Service) ownerAndGrants(ctx context.Context, q *dbq.Queries, resourceType string, id uuid.UUID) (uuid.UUID, []authz.Grant, error) {
	var (
		owner pgtype.UUID
		raw   []rawGrant
		err   error
	)
	switch resourceType {
	case "connection":
		owner, err = q.GetConnectionOwner(ctx, pg(id))
		if err == nil {
			rows, e := q.ListConnectionGrants(ctx, pg(id))
			err = e
			for _, r := range rows {
				raw = append(raw, rawGrant{r.GranteeID, r.Capabilities})
			}
		}
	case "mcp_server":
		owner, err = q.GetMCPServerOwner(ctx, pg(id))
		if err == nil {
			rows, e := q.ListMCPServerGrants(ctx, pg(id))
			err = e
			for _, r := range rows {
				raw = append(raw, rawGrant{r.GranteeID, r.Capabilities})
			}
		}
	case "exec_endpoint":
		owner, err = q.GetExecEndpointOwner(ctx, pg(id))
		if err == nil {
			rows, e := q.ListExecEndpointGrants(ctx, pg(id))
			err = e
			for _, r := range rows {
				raw = append(raw, rawGrant{r.GranteeID, r.Capabilities})
			}
		}
	case "git_credential":
		owner, err = q.GetGitCredentialOwner(ctx, pg(id))
		if err == nil {
			rows, e := q.ListGitCredentialGrants(ctx, pg(id))
			err = e
			for _, r := range rows {
				raw = append(raw, rawGrant{r.GranteeID, r.Capabilities})
			}
		}
	default:
		return uuid.Nil, nil, service.Detail(service.ErrInvalidInput, "unknown resource type %q", resourceType)
	}
	if err != nil {
		return uuid.Nil, nil, service.ErrNotFound
	}
	grants := make([]authz.Grant, len(raw))
	for i, r := range raw {
		grants[i] = authz.Grant{GranteeID: uuid.UUID(r.grantee.Bytes), Capabilities: r.caps}
	}
	return uuid.UUID(owner.Bytes), grants, nil
}

type rawGrant struct {
	grantee pgtype.UUID
	caps    []string
}

// GrantResource grants capabilities on a resource to a grantee. The caller must
// hold the manage capability on the resource.
func (s *Service) GrantResource(ctx context.Context, p authz.Principal, resourceType string, resourceID, granteeID uuid.UUID, caps []string) error {
	if !validCaps(caps) {
		return service.Detail(service.ErrInvalidInput, "capabilities must be a non-empty subset of view/bind/manage")
	}
	q := dbq.New(s.db.Pool())
	owner, grants, err := s.ownerAndGrants(ctx, q, resourceType, resourceID)
	if err != nil {
		return err
	}
	if !p.HasResourceCapability(owner, grants, authz.CapManage) {
		return service.Detail(service.ErrForbidden, "you do not have manage access to this resource")
	}
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
	return nil
}

// RevokeResourceGrant deletes a grant by id. The caller must hold manage on the
// resource the grant belongs to.
func (s *Service) RevokeResourceGrant(ctx context.Context, p authz.Principal, resourceType string, resourceID, grantID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	owner, grants, err := s.ownerAndGrants(ctx, q, resourceType, resourceID)
	if err != nil {
		return err
	}
	if !p.HasResourceCapability(owner, grants, authz.CapManage) {
		return service.Detail(service.ErrForbidden, "you do not have manage access to this resource")
	}
	return q.RevokeResourceGrant(ctx, pg(grantID))
}

// ListResourceGrants returns a resource's grants. The caller must hold view on
// the resource.
func (s *Service) ListResourceGrants(ctx context.Context, p authz.Principal, resourceType string, resourceID uuid.UUID) ([]ResourceGrant, error) {
	q := dbq.New(s.db.Pool())
	owner, grants, err := s.ownerAndGrants(ctx, q, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	if !p.HasResourceCapability(owner, grants, authz.CapView) {
		return nil, service.Detail(service.ErrForbidden, "you do not have view access to this resource")
	}
	out := make([]ResourceGrant, len(grants))
	for i, g := range grants {
		out[i] = ResourceGrant{GranteeID: g.GranteeID, Capabilities: g.Capabilities}
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

// RevokeModelGrant removes a model entitlement. Tenant-admin only.
func (s *Service) RevokeModelGrant(ctx context.Context, p authz.Principal, grantID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantModelGrantManage, uuid.Nil); err != nil {
		return err
	}
	return q.RevokeModelGrant(ctx, pg(grantID))
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
