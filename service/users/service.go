// Package users owns the tenant-wide user directory: reads (List /
// ListDetail / Get / Lookup) at TenantUserView, and admin mutators
// (Create / UpdateRole / Delete) at TenantUserManage. Every method
// gates through authz.Authorize so the policy table is the one place
// the access matrix is editable.
package users

import (
	"context"
	"fmt"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// authorizeRead is the one read gate every method runs first. Gating
// goes through authz.Authorize (TenantUserView), not an inline
// IsAuthenticatedUser check — that's the rule (airlock/AGENTS.md): no
// service method open-codes its level; every action sits in the
// policy table so a single edit moves the bar everywhere.
func (s *Service) authorizeRead(ctx context.Context, p authz.Principal) error {
	q := dbq.New(s.db.Pool())
	return authz.Authorize(ctx, q, p, authz.TenantUserView, uuid.Nil)
}

// BridgeStopper is the narrow surface Delete uses to pre-cancel the
// BridgeManager pollers for a user's bridges before the DB CASCADE
// removes the rows. Defined as an interface to avoid importing
// trigger (cycle risk) and to keep the users service testable.
type BridgeStopper interface {
	RemoveBridgesByOwner(ctx context.Context, ownerID uuid.UUID) error
}

type Service struct {
	db      *db.DB
	bridges BridgeStopper
	logger  *zap.Logger
}

// New wires the users service. bridges may be nil for tests that
// don't exercise the Delete cascade path; production wires it to the
// BridgeManager.
func New(d *db.DB, bridges BridgeStopper, logger *zap.Logger) *Service {
	if d == nil {
		panic("users: db is required")
	}
	if logger == nil {
		panic("users: logger is required")
	}
	return &Service{db: d, bridges: bridges, logger: logger}
}

// Summary is the slim user shape every caller needs — id, identity
// fields, and tenant role. No password hash, no oidc_sub, no
// timestamps; the wider Detail type carries those for admin-only
// callers.
type Summary struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	TenantRole  string    `json:"tenant_role"`
}

// Detail is the full admin-visible user row — adds the OIDC subject,
// timestamps, and password-reset flag. Returned only by admin-gated
// methods (ListDetail / GetDetail) because oidc_sub leaks SSO
// identity to other tenants if surfaced widely.
type Detail struct {
	Summary
	OIDCSub            string             `json:"oidc_sub"`
	MustChangePassword bool               `json:"must_change_password"`
	CreatedAt          pgtype.Timestamptz `json:"created_at"`
	UpdatedAt          pgtype.Timestamptz `json:"updated_at"`
}

func detailFromRow(u dbq.User) Detail {
	return Detail{
		Summary: Summary{
			ID:          uuid.UUID(u.ID.Bytes),
			Email:       u.Email,
			DisplayName: u.DisplayName,
			TenantRole:  u.TenantRole,
		},
		OIDCSub:            u.OidcSub,
		MustChangePassword: u.MustChangePassword,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
	}
}

// List returns every user in the tenant in stable order (by created_at,
// matching the underlying ListUsers query). Available to any
// authenticated user — the same access level the member-picker
// dropdown uses, since invite flows need to see candidate users.
func (s *Service) List(ctx context.Context, p authz.Principal) ([]Summary, error) {
	if err := s.authorizeRead(ctx, p); err != nil {
		return nil, err
	}
	q := dbq.New(s.db.Pool())
	rows, err := q.ListUsers(ctx)
	if err != nil {
		s.logger.Error("users: list failed", zap.Error(err))
		return nil, err
	}
	out := make([]Summary, len(rows))
	for i, u := range rows {
		out[i] = Summary{
			ID:          uuid.UUID(u.ID.Bytes),
			Email:       u.Email,
			DisplayName: u.DisplayName,
			TenantRole:  u.TenantRole,
		}
	}
	return out, nil
}

// Get returns one user by id. ErrNotFound for an unknown id. Same
// auth shape as List — any authenticated user can look up another by
// id (e.g. whoami expanding the principal's email field).
func (s *Service) Get(ctx context.Context, p authz.Principal, userID uuid.UUID) (Summary, error) {
	if err := s.authorizeRead(ctx, p); err != nil {
		return Summary{}, err
	}
	q := dbq.New(s.db.Pool())
	row, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: userID, Valid: true})
	if err != nil {
		return Summary{}, service.ErrNotFound
	}
	return Summary{
		ID:          uuid.UUID(row.ID.Bytes),
		Email:       row.Email,
		DisplayName: row.DisplayName,
		TenantRole:  row.TenantRole,
	}, nil
}

// ListDetail returns every user with the full admin-visible Detail
// shape (Summary + oidc_sub + timestamps + must_change_password).
// Gated on TenantUserManage — only tenant admins should see the
// SSO subject claim or password-reset state.
func (s *Service) ListDetail(ctx context.Context, p authz.Principal) ([]Detail, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantUserManage, uuid.Nil); err != nil {
		return nil, err
	}
	rows, err := q.ListUsers(ctx)
	if err != nil {
		s.logger.Error("users: list-detail failed", zap.Error(err))
		return nil, err
	}
	out := make([]Detail, len(rows))
	for i, u := range rows {
		out[i] = detailFromRow(u)
	}
	return out, nil
}

// CreateRequest is the input to Create. Role "" defaults to "user".
type CreateRequest struct {
	Email       string
	DisplayName string
	TenantRole  string
}

// Create provisions a user with a server-generated temporary password and
// must_change_password=true, so the recipient is forced to secure the account
// (set a strong password or register a passkey) on first login. It returns the
// one-time temp password for the admin to hand off; it is never stored in
// plaintext or retrievable again. Admin-gated (TenantUserManage). ErrConflict
// on duplicate email.
func (s *Service) Create(ctx context.Context, p authz.Principal, req CreateRequest) (Detail, string, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantUserManage, uuid.Nil); err != nil {
		return Detail{}, "", err
	}
	if req.Email == "" {
		return Detail{}, "", service.Detail(service.ErrInvalidInput, "email is required")
	}
	role := req.TenantRole
	if role == "" {
		role = "user"
	}
	if !validTenantRole(role) {
		return Detail{}, "", service.Detail(service.ErrInvalidInput, "tenant_role must be user|manager|admin")
	}
	tempPassword, err := auth.GenerateTempPassword()
	if err != nil {
		s.logger.Error("users: generate temp password failed", zap.Error(err))
		return Detail{}, "", err
	}
	hash, err := auth.HashPassword(tempPassword)
	if err != nil {
		s.logger.Error("users: hash password failed", zap.Error(err))
		return Detail{}, "", err
	}
	row, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:              req.Email,
		DisplayName:        req.DisplayName,
		PasswordHash:       pgtype.Text{String: hash, Valid: true},
		TenantRole:         role,
		MustChangePassword: true,
	})
	if err != nil {
		// CreateUser surfaces a uniqueness violation here — translate to
		// ErrConflict so the handler returns 409 without inspecting pg
		// error codes.
		return Detail{}, "", service.Detail(service.ErrConflict, "user already exists")
	}
	return detailFromRow(row), tempPassword, nil
}

// UpdateRole changes a user's tenant role. Admin-gated. Refuses the
// self-change case (callers can't demote themselves out of admin) and refuses
// to demote the last admin.
// ErrInvalidInput on unknown role; ErrNotFound when the user is gone.
func (s *Service) UpdateRole(ctx context.Context, p authz.Principal, targetID uuid.UUID, role string) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantUserManage, uuid.Nil); err != nil {
		return err
	}
	if p.UserID == targetID {
		return service.Detail(service.ErrInvalidInput, "cannot change your own role")
	}
	if !validTenantRole(role) {
		return service.Detail(service.ErrInvalidInput, "tenant_role must be user|manager|admin")
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := q.WithTx(tx)
	if err := qtx.LockUsersForAdminMutation(ctx); err != nil {
		return err
	}
	target, err := qtx.GetUserByID(ctx, pgtype.UUID{Bytes: targetID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if target.TenantRole == "admin" && role != "admin" {
		count, err := qtx.CountTenantAdmins(ctx)
		if err != nil {
			return err
		}
		if count <= 1 {
			return service.Detail(ErrLastAdmin, "cannot demote the last admin")
		}
	}
	if err := qtx.UpdateUserRole(ctx, dbq.UpdateUserRoleParams{
		ID:         pgtype.UUID{Bytes: targetID, Valid: true},
		TenantRole: role,
	}); err != nil {
		s.logger.Error("users: update role failed", zap.Error(err))
		return err
	}
	return tx.Commit(ctx)
}

// ErrLastAdmin — the one named guard Delete enforces beyond the
// generic ones. Wraps ErrInvalidInput so HTTPStatus maps to 400.
var ErrLastAdmin = fmt.Errorf("cannot remove the last admin: %w", service.ErrInvalidInput)

// Delete removes a user. Admin-gated. Refuses self-deletion and
// refuses deletion of the last remaining admin (would lock the
// tenant out of TenantUserManage).
func (s *Service) Delete(ctx context.Context, p authz.Principal, targetID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantUserManage, uuid.Nil); err != nil {
		return err
	}
	if p.UserID == targetID {
		return service.Detail(service.ErrInvalidInput, "cannot delete yourself")
	}
	if _, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: targetID, Valid: true}); err != nil {
		return service.ErrNotFound
	}
	// Pre-stop the user's bridge pollers. The DB CASCADE on
	// bridges.owner_id removes the rows during DeleteUser; if we don't
	// cancel the goroutines first, they keep polling getUpdates on the
	// (now-deleted) row until next transient failure, racing on the
	// bot token with any replacement bridge that happens to reuse the
	// same id.
	if s.bridges != nil {
		if err := s.bridges.RemoveBridgesByOwner(ctx, targetID); err != nil {
			s.logger.Warn("users: stop bridges-by-owner failed; proceeding with delete",
				zap.String("user_id", targetID.String()), zap.Error(err))
		}
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := q.WithTx(tx)
	if err := qtx.LockUsersForAdminMutation(ctx); err != nil {
		return err
	}
	target, err := qtx.GetUserByID(ctx, pgtype.UUID{Bytes: targetID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if target.TenantRole == "admin" {
		count, err := qtx.CountTenantAdmins(ctx)
		if err != nil {
			return err
		}
		if count <= 1 {
			return service.Detail(ErrLastAdmin, "cannot delete the last admin")
		}
	}
	if err := qtx.DeleteUser(ctx, pgtype.UUID{Bytes: targetID, Valid: true}); err != nil {
		s.logger.Error("users: delete failed", zap.Error(err))
		return err
	}
	return tx.Commit(ctx)
}

func validTenantRole(s string) bool {
	return s == "user" || s == "manager" || s == "admin"
}

// Lookup resolves a user identifier (UUID OR email) to a Summary.
// Used by tools like add_agent_member where the operator may type
// either form. ErrInvalidInput for empty input; ErrNotFound when the
// identifier matches no user.
func (s *Service) Lookup(ctx context.Context, p authz.Principal, identifier string) (Summary, error) {
	if err := s.authorizeRead(ctx, p); err != nil {
		return Summary{}, err
	}
	if identifier == "" {
		return Summary{}, service.Detail(service.ErrInvalidInput, "user is required")
	}
	if id, err := uuid.Parse(identifier); err == nil {
		return s.Get(ctx, p, id)
	}
	q := dbq.New(s.db.Pool())
	row, err := q.GetUserByEmail(ctx, identifier)
	if err != nil {
		return Summary{}, service.Detail(service.ErrNotFound, "user %q not found", identifier)
	}
	return Summary{
		ID:          uuid.UUID(row.ID.Bytes),
		Email:       row.Email,
		DisplayName: row.DisplayName,
		TenantRole:  row.TenantRole,
	}, nil
}
