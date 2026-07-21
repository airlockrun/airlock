package authz

import (
	"context"
	"errors"

	"github.com/airlockrun/airlock/apperr"
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
	owner, grants, err := loadResourceAccess(ctx, q, resourceType, resourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.ErrNotFound
	}
	if err != nil {
		return err
	}
	if !p.HasResourceCapability(owner, grants, capability) {
		return apperr.ErrForbidden
	}
	return nil
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
	case "exec_endpoint":
		return q.LockExecEndpointResource(ctx, id)
	case "git_credential":
		return q.LockGitCredentialResource(ctx, id)
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
	owner, grants, err := loadResourceAccess(ctx, q, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	var capabilities []string
	for _, capability := range []string{CapView, CapBind, CapManage} {
		if p.HasResourceCapability(owner, grants, capability) {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities, nil
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
	case "exec_endpoint":
		owner, err = q.GetExecEndpointOwner(ctx, id)
		if err == nil {
			rows, listErr := q.ListExecEndpointGrants(ctx, id)
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
	default:
		return uuid.Nil, nil, apperr.ErrInvalidInput
	}
	if err != nil {
		return uuid.Nil, nil, err
	}
	return uuid.UUID(owner.Bytes), grants, nil
}
