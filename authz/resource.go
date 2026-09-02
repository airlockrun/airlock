package authz

import (
	"context"
	"errors"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// AuthorizeResource applies the central authenticated-user policy and then the
// requested capability to a concrete management-plane resource.
func AuthorizeResource(ctx context.Context, q *dbq.Queries, p Principal, action Action, resourceType string, resourceID uuid.UUID) error {
	if err := Authorize(ctx, q, p, action, uuid.Nil); err != nil {
		return err
	}
	capability := resourceCapability(action)
	if !resourceSupportsCapability(resourceType, capability) {
		return apperr.ErrInvalidInput
	}
	owner, grants, err := loadResourceAccess(ctx, q, resourceType, resourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.ErrNotFound
	}
	if err != nil {
		return err
	}
	if capability == CapView && p.TenantRole == auth.RoleAdmin {
		return nil
	}
	if !p.HasResourceCapability(owner, grants, capability) {
		return apperr.ErrForbidden
	}
	return nil
}

// AuthorizeResourceTransfer permits the current owner or a tenant administrator
// to explicitly transfer ownership. It grants no other resource capability.
func AuthorizeResourceTransfer(ctx context.Context, q *dbq.Queries, p Principal, resourceType string, resourceID uuid.UUID) error {
	if err := Authorize(ctx, q, p, ResourceTransfer, uuid.Nil); err != nil {
		return err
	}
	owner, err := ResourceOwner(ctx, q, resourceType, resourceID)
	if err != nil {
		return err
	}
	if p.TenantRole == auth.RoleAdmin || p.HasResourceCapability(owner, nil, CapManage) {
		return nil
	}
	return apperr.ErrForbidden
}

// LockResource serializes capability changes and credential replacement on a
// concrete resource. Callers lock need rows first when an operation has both.
func LockResource(ctx context.Context, q *dbq.Queries, resourceType string, resourceID uuid.UUID) error {
	id := pgtype.UUID{Bytes: resourceID, Valid: true}
	switch resourceType {
	case "connection":
		return q.LockConnectionResource(ctx, id)
	case "mcp_server":
		return q.LockMCPServerResource(ctx, id)
	case "git_credential":
		return q.LockGitCredentialResource(ctx, id)
	case "connector":
		return q.LockConnectorResource(ctx, id)
	case "host":
		return q.LockHostResource(ctx, id)
	case "connector_target_group":
		return q.LockConnectorTargetGroup(ctx, id)
	default:
		return apperr.ErrInvalidInput
	}
}

// ResourceCapabilities returns the caller's complete capability set after
// requiring bind access. It is used by the need picker, where bind-only
// resources remain visible while manage controls shared authorization changes.
func ResourceCapabilities(ctx context.Context, q *dbq.Queries, p Principal, resourceType string, resourceID uuid.UUID) ([]string, error) {
	if err := AuthorizeResource(ctx, q, p, ResourceBind, resourceType, resourceID); err != nil {
		return nil, err
	}
	return resourceCapabilities(ctx, q, p, resourceType, resourceID)
}

// ResourceCapabilitiesForView returns the caller's capabilities after a view
// gate, allowing detail surfaces to represent view-only grants accurately.
func ResourceCapabilitiesForView(ctx context.Context, q *dbq.Queries, p Principal, resourceType string, resourceID uuid.UUID) ([]string, error) {
	if err := AuthorizeResource(ctx, q, p, ResourceView, resourceType, resourceID); err != nil {
		return nil, err
	}
	return resourceCapabilities(ctx, q, p, resourceType, resourceID)
}

// ResourceCapabilitiesForDetail permits either view or manage access. Callers
// must project interface/consumer data only when the returned set includes view.
func ResourceCapabilitiesForDetail(ctx context.Context, q *dbq.Queries, p Principal, resourceType string, resourceID uuid.UUID) ([]string, error) {
	if err := AuthorizeResource(ctx, q, p, ResourceView, resourceType, resourceID); err != nil {
		if !errors.Is(err, apperr.ErrForbidden) {
			return nil, err
		}
		if err := AuthorizeResource(ctx, q, p, ResourceManage, resourceType, resourceID); err != nil {
			return nil, err
		}
	}
	return resourceCapabilities(ctx, q, p, resourceType, resourceID)
}

func resourceCapabilities(ctx context.Context, q *dbq.Queries, p Principal, resourceType string, resourceID uuid.UUID) ([]string, error) {
	owner, grants, err := loadResourceAccess(ctx, q, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	var capabilities []string
	for _, capability := range SupportedResourceCapabilities(resourceType) {
		if capability == CapView && p.TenantRole == auth.RoleAdmin {
			capabilities = append(capabilities, capability)
			continue
		}
		if p.HasResourceCapability(owner, grants, capability) {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities, nil
}

// SupportedResourceCapabilities returns the capabilities valid for a resource
// type in stable display order.
func SupportedResourceCapabilities(resourceType string) []string {
	if resourceType == "host" {
		return []string{CapView, CapManage}
	}
	switch resourceType {
	case "connection", "mcp_server", "git_credential", "connector", "connector_target_group":
		return []string{CapView, CapBind, CapManage}
	default:
		return nil
	}
}

func resourceSupportsCapability(resourceType, capability string) bool {
	for _, supported := range SupportedResourceCapabilities(resourceType) {
		if supported == capability {
			return true
		}
	}
	return false
}

// ResourceOwner returns the resource's current owner after validating its type.
func ResourceOwner(ctx context.Context, q *dbq.Queries, resourceType string, resourceID uuid.UUID) (uuid.UUID, error) {
	owner, _, err := loadResourceAccess(ctx, q, resourceType, resourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, apperr.ErrNotFound
	}
	return owner, err
}

func resourceCapability(action Action) string {
	switch action {
	case ResourceView:
		return CapView
	case ResourceBind:
		return CapBind
	case ResourceManage:
		return CapManage
	default:
		panic("authz: action is not a resource capability action: " + string(action))
	}
}

func loadResourceAccess(ctx context.Context, q *dbq.Queries, resourceType string, resourceID uuid.UUID) (uuid.UUID, []Grant, error) {
	id := pgtype.UUID{Bytes: resourceID, Valid: true}
	var (
		owner  pgtype.UUID
		grants []Grant
		err    error
	)
	switch resourceType {
	case "connection":
		owner, err = q.GetConnectionOwner(ctx, id)
		if err == nil {
			rows, listErr := q.ListConnectionGrants(ctx, id)
			err = listErr
			for _, row := range rows {
				grants = append(grants, Grant{GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
			}
		}
	case "mcp_server":
		owner, err = q.GetMCPServerOwner(ctx, id)
		if err == nil {
			rows, listErr := q.ListMCPServerGrants(ctx, id)
			err = listErr
			for _, row := range rows {
				grants = append(grants, Grant{GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
			}
		}
	case "git_credential":
		owner, err = q.GetGitCredentialOwner(ctx, id)
		if err == nil {
			rows, listErr := q.ListGitCredentialGrants(ctx, id)
			err = listErr
			for _, row := range rows {
				grants = append(grants, Grant{GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
			}
		}
	case "connector":
		owner, err = q.GetConnectorOwner(ctx, id)
		if err == nil {
			rows, listErr := q.ListConnectorGrants(ctx, id)
			err = listErr
			for _, row := range rows {
				grants = append(grants, Grant{GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
			}
		}
	case "host":
		owner, err = q.GetHostOwner(ctx, id)
		if err == nil {
			rows, listErr := q.ListHostGrants(ctx, id)
			err = listErr
			for _, row := range rows {
				grants = append(grants, Grant{GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
			}
		}
	case "connector_target_group":
		owner, err = q.GetConnectorTargetGroupOwner(ctx, id)
		if err == nil {
			rows, listErr := q.ListConnectorTargetGroupGrants(ctx, id)
			err = listErr
			for _, row := range rows {
				grants = append(grants, Grant{GranteeID: uuid.UUID(row.GranteeID.Bytes), Capabilities: row.Capabilities})
			}
		}
	default:
		return uuid.Nil, nil, apperr.ErrInvalidInput
	}
	if err != nil {
		return uuid.Nil, nil, err
	}
	return uuid.UUID(owner.Bytes), grants, nil
}
