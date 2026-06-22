// Package providers owns the tenant-wide LLM provider catalog: rows
// in the providers table, their encrypted API keys, and the lifecycle
// (create / list / update / delete). Mutations gate through
// authz.Authorize(TenantProviderManage) (admin); List gates through
// TenantProviderView (manager+) so anyone who can configure an agent's
// models can resolve provider id→name. API keys are write-once: set on
// create/update, encrypted at rest, and never returned to any caller.
package providers

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type Service struct {
	db     *db.DB
	enc    secrets.Store
	logger *zap.Logger
}

func New(d *db.DB, enc secrets.Store, logger *zap.Logger) *Service {
	if d == nil {
		panic("providers: db is required")
	}
	if enc == nil {
		panic("providers: encryptor is required")
	}
	if logger == nil {
		panic("providers: logger is required")
	}
	return &Service{db: d, enc: enc, logger: logger}
}

// Result is the persisted row. The API key is never included — it's
// write-once and stays encrypted at rest; the row's has-key state is
// derived from the ciphertext column (see convert.ProviderToProto).
type Result struct {
	Row dbq.Provider
}

type CreateRequest struct {
	ProviderID  string // catalog id (e.g. "openai")
	Slug        string
	DisplayName string
	APIKey      string
	BaseURL     string
}

type UpdateRequest struct {
	Slug        string
	DisplayName string
	BaseURL     string
	APIKey      string // empty → leave existing ciphertext
	IsEnabled   *bool  // nil → leave existing flag
}

func (s *Service) authorize(ctx context.Context, p authz.Principal) error {
	q := dbq.New(s.db.Pool())
	return authz.Authorize(ctx, q, p, authz.TenantProviderManage, uuid.Nil)
}

// authorizeView gates List at manager+ (read of non-secret provider rows for
// model selection), distinct from the admin-only mutation gate.
func (s *Service) authorizeView(ctx context.Context, p authz.Principal) error {
	q := dbq.New(s.db.Pool())
	return authz.Authorize(ctx, q, p, authz.TenantProviderView, uuid.Nil)
}

func (s *Service) Create(ctx context.Context, p authz.Principal, req CreateRequest) (Result, error) {
	if err := s.authorize(ctx, p); err != nil {
		return Result{}, err
	}
	if req.ProviderID == "" {
		return Result{}, service.Detail(service.ErrInvalidInput, "provider_id is required")
	}
	if req.Slug == "" {
		return Result{}, service.Detail(service.ErrInvalidInput, "slug is required")
	}
	if req.APIKey == "" {
		return Result{}, service.Detail(service.ErrInvalidInput, "api_key is required")
	}

	catalog, err := solprovider.AllProviders()
	if err != nil {
		s.logger.Error("load provider catalog failed", zap.Error(err))
		return Result{}, err
	}
	if _, ok := catalog[req.ProviderID]; !ok {
		return Result{}, service.Detail(service.ErrInvalidInput, "unknown provider_id: %s", req.ProviderID)
	}

	// Pre-generate the row UUID so the api_key ciphertext is bound to
	// it via AAD before we INSERT. Per-row scoping prevents one row's
	// key from being decrypted under another row's path.
	id := uuid.New()
	encrypted, err := s.enc.Put(ctx, "provider/"+id.String()+"/api_key", req.APIKey)
	if err != nil {
		s.logger.Error("encrypt api key failed", zap.Error(err))
		return Result{}, err
	}

	q := dbq.New(s.db.Pool())
	row, err := q.CreateProvider(ctx, dbq.CreateProviderParams{
		ID:          pgtype.UUID{Bytes: id, Valid: true},
		CatalogID:   req.ProviderID,
		Slug:        req.Slug,
		DisplayName: req.DisplayName,
		ApiKey:      encrypted,
		BaseUrl:     req.BaseURL,
		IsEnabled:   true,
	})
	if err != nil {
		s.logger.Error("create provider failed", zap.Error(err))
		return Result{}, err
	}
	return Result{Row: row}, nil
}

func (s *Service) List(ctx context.Context, p authz.Principal) ([]Result, error) {
	if err := s.authorizeView(ctx, p); err != nil {
		return nil, err
	}
	q := dbq.New(s.db.Pool())
	rows, err := q.ListProviders(ctx)
	if err != nil {
		s.logger.Error("list providers failed", zap.Error(err))
		return nil, err
	}
	out := make([]Result, len(rows))
	for i, row := range rows {
		out[i] = Result{Row: row}
	}
	return out, nil
}

func (s *Service) Update(ctx context.Context, p authz.Principal, id uuid.UUID, req UpdateRequest) (Result, error) {
	if err := s.authorize(ctx, p); err != nil {
		return Result{}, err
	}
	params := dbq.UpdateProviderParams{
		ID:          pgtype.UUID{Bytes: id, Valid: true},
		DisplayName: req.DisplayName,
		Slug:        req.Slug,
		BaseUrl:     req.BaseURL,
	}
	if req.APIKey != "" {
		encrypted, err := s.enc.Put(ctx, "provider/"+id.String()+"/api_key", req.APIKey)
		if err != nil {
			s.logger.Error("encrypt api key failed", zap.Error(err))
			return Result{}, err
		}
		params.UpdateApiKey = true
		params.ApiKey = encrypted
	}
	if req.IsEnabled != nil {
		params.UpdateIsEnabled = true
		params.IsEnabled = *req.IsEnabled
	}
	q := dbq.New(s.db.Pool())
	row, err := q.UpdateProvider(ctx, params)
	if err != nil {
		s.logger.Error("update provider failed", zap.Error(err))
		return Result{}, err
	}
	return Result{Row: row}, nil
}

func (s *Service) Delete(ctx context.Context, p authz.Principal, id uuid.UUID) error {
	if err := s.authorize(ctx, p); err != nil {
		return err
	}
	q := dbq.New(s.db.Pool())
	if err := q.DeleteProvider(ctx, pgtype.UUID{Bytes: id, Valid: true}); err != nil {
		s.logger.Error("delete provider failed", zap.Error(err))
		return err
	}
	return nil
}
