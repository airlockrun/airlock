// Package gitcredentials owns the per-user git PAT credential surface
// (list / create / delete). The token plaintext is encrypted at rest
// under "git_credential/{id}/token" via secrets.Store and is never
// returned by any method on this Service — DTOs deliberately omit it,
// so a caller can't accidentally serialize the secret. Per-row runtime
// lookups that need the encrypted ref (agent build pipeline) hit
// dbq.GetGitCredential directly with their own ownership check; this
// service is for the operator's own CRUD against their credential
// list.
package gitcredentials

import (
	"context"
	"errors"
	"strings"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Service is the per-user git PAT layer. All methods gate on the
// principal being an authenticated user; there is no agent axis.
type Service struct {
	db        *db.DB
	encryptor secrets.Store
	logger    *zap.Logger
}

func New(d *db.DB, enc secrets.Store, logger *zap.Logger) *Service {
	if d == nil {
		panic("gitcredentials: db is required")
	}
	if enc == nil {
		panic("gitcredentials: encryptor is required")
	}
	if logger == nil {
		panic("gitcredentials: logger is required")
	}
	return &Service{db: d, encryptor: enc, logger: logger}
}

// Credential is the wire shape the handler / sysagent tool sees. No
// token field exists — by design, so accidental serialization can't
// leak the secret.
type Credential struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	Type            string
	Name            string
	GithubInstallID string
	CreatedAt       pgtype.Timestamptz
	LastUsedAt      pgtype.Timestamptz
}

// CreateRequest is the input for Create. Type "" defaults to "pat".
type CreateRequest struct {
	Name  string
	Token string
	Type  string
}

// List returns the caller's own credentials, omitting token_ref bytes.
// Ordered by name for stable rendering.
func (s *Service) List(ctx context.Context, p authz.Principal) ([]Credential, error) {
	if !p.IsAuthenticatedUser() {
		return nil, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	rows, err := q.ListGitCredentialsByUser(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		s.logger.Error("list git credentials failed", zap.Error(err))
		return nil, err
	}
	out := make([]Credential, len(rows))
	for i, r := range rows {
		out[i] = Credential{
			ID:              uuid.UUID(r.ID.Bytes),
			UserID:          uuid.UUID(r.UserID.Bytes),
			Type:            r.Type,
			Name:            r.Name,
			GithubInstallID: r.GithubInstallID,
			CreatedAt:       r.CreatedAt,
			LastUsedAt:      r.LastUsedAt,
		}
	}
	return out, nil
}

// Create encrypts the token under a generated id and persists the row.
// Returns ErrInvalidInput (Detail-wrapped) on missing name/token or
// unsupported type, ErrConflict on a duplicate name for this user.
func (s *Service) Create(ctx context.Context, p authz.Principal, req CreateRequest) (Credential, error) {
	if !p.IsAuthenticatedUser() {
		return Credential{}, service.ErrUnauthorized
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return Credential{}, service.Detail(service.ErrInvalidInput, "name is required")
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return Credential{}, service.Detail(service.ErrInvalidInput, "token is required")
	}
	// v1 only supports PAT; github_app is a v2 type. Reject unknowns
	// rather than silently coercing — fail loud (airlock CLAUDE.md).
	credType := req.Type
	if credType == "" {
		credType = "pat"
	}
	if credType != "pat" {
		return Credential{}, service.Detail(service.ErrInvalidInput, "type must be \"pat\" (v1)")
	}

	// Pre-generate the id so the ciphertext is AAD-bound to it before
	// INSERT — same shape as the providers / connections pattern.
	id := uuid.New()
	encrypted, err := s.encryptor.Put(ctx, "git_credential/"+id.String()+"/token", token)
	if err != nil {
		s.logger.Error("encrypt git credential token failed", zap.Error(err))
		return Credential{}, err
	}

	q := dbq.New(s.db.Pool())
	row, err := q.CreateGitCredential(ctx, dbq.CreateGitCredentialParams{
		ID:              pgtype.UUID{Bytes: id, Valid: true},
		UserID:          pgtype.UUID{Bytes: p.UserID, Valid: true},
		Type:            "pat",
		Name:            name,
		TokenRef:        encrypted,
		GithubInstallID: "",
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Credential{}, service.Detail(service.ErrConflict, "a credential with that name already exists")
		}
		s.logger.Error("create git credential failed", zap.Error(err))
		return Credential{}, err
	}
	return Credential{
		ID:              uuid.UUID(row.ID.Bytes),
		UserID:          uuid.UUID(row.UserID.Bytes),
		Type:            row.Type,
		Name:            row.Name,
		GithubInstallID: row.GithubInstallID,
		CreatedAt:       row.CreatedAt,
		LastUsedAt:      row.LastUsedAt,
	}, nil
}

// Delete removes the caller's credential by id. Owner-scoped at the
// query level via DELETE WHERE id = $1 AND user_id = $2, so a mismatched
// owner yields no-op (we still report success — same idempotence the
// raw handler had).
func (s *Service) Delete(ctx context.Context, p authz.Principal, id uuid.UUID) error {
	if !p.IsAuthenticatedUser() {
		return service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	if err := q.DeleteGitCredential(ctx, dbq.DeleteGitCredentialParams{
		ID:     pgtype.UUID{Bytes: id, Valid: true},
		UserID: pgtype.UUID{Bytes: p.UserID, Valid: true},
	}); err != nil {
		s.logger.Error("delete git credential failed", zap.Error(err))
		return err
	}
	return nil
}
