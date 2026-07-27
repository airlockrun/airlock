// Package providers owns configured LLM provider rows, optional encrypted API
// keys, confirmed endpoint-specific models, and model discovery. Mutations gate through
// authz.Authorize(TenantProviderManage) (admin); List gates through
// TenantProviderView (manager+) so anyone who can configure an agent's
// models can resolve provider IDs to names. Configured keys are encrypted at
// rest and never returned; no-auth OpenAI-compatible rows store an empty key.
package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/networkpolicy"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const (
	openAICompatibleProviderID = "openai-compatible"
	discoveryTimeout           = 5 * time.Second
	maxDiscoveryResponseBytes  = 1 << 20
	maxDiscoveredModels        = 10000
)

var providerSlugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type Service struct {
	db     *db.DB
	enc    secrets.Store
	http   *http.Client
	logger *zap.Logger
}

func New(d *db.DB, enc secrets.Store, client *http.Client, logger *zap.Logger) *Service {
	if d == nil {
		panic("providers: db is required")
	}
	if enc == nil {
		panic("providers: encryptor is required")
	}
	if client == nil {
		panic("providers: HTTP client is required")
	}
	if logger == nil {
		panic("providers: logger is required")
	}
	return &Service{db: d, enc: enc, http: newDiscoveryClient(client), logger: logger}
}

func newDiscoveryClient(client *http.Client) *http.Client {
	strictClient := *client
	strictClient.Timeout = discoveryTimeout
	if strictClient.Transport == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		strictClient.Transport = transport
	}
	strictClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not allowed")
	}
	return &strictClient
}

// Result is the persisted row. The API key is never included; the row's
// has-key state is derived from the ciphertext column.
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
	APIKey      string // empty leaves the existing ciphertext unless ClearAPIKey is set
	ClearAPIKey bool
	IsEnabled   *bool // nil → leave existing flag
}

type Model struct {
	ModelID           string
	DisplayName       string
	ToolCall          bool
	Reasoning         bool
	Vision            bool
	ContextLimit      int32
	OutputLimit       int32
	StructuredOutputs bool
	IncludeUsage      bool
}

type ModelCandidate struct {
	ModelID string
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
	if err := validateSlug(req.Slug); err != nil {
		return Result{}, err
	}
	if req.APIKey == "" && req.ProviderID != openAICompatibleProviderID {
		return Result{}, service.Detail(service.ErrInvalidInput, "api_key is required")
	}
	if err := validateProviderBaseURL(req.ProviderID, req.BaseURL); err != nil {
		return Result{}, err
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
	encrypted := ""
	if req.APIKey != "" {
		encrypted, err = s.enc.Put(ctx, "provider/"+id.String()+"/api_key", req.APIKey)
		if err != nil {
			s.logger.Error("encrypt api key failed", zap.Error(err))
			return Result{}, err
		}
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
		if isProviderSlugViolation(err) {
			return Result{}, service.Detail(service.ErrConflict, "provider slug already exists for provider_id")
		}
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
	if req.APIKey != "" && req.ClearAPIKey {
		return Result{}, service.Detail(service.ErrInvalidInput, "api_key and clear_api_key are mutually exclusive")
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	existing, err := q.GetProviderByIDForUpdate(ctx, pgtype.UUID{Bytes: id, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, service.ErrNotFound
		}
		return Result{}, err
	}
	slug := existing.Slug
	if req.Slug != "" {
		slug = req.Slug
	}
	if err := validateSlug(slug); err != nil {
		return Result{}, err
	}
	baseURL := existing.BaseUrl
	if req.BaseURL != "" {
		baseURL = req.BaseURL
	}
	if err := validateProviderBaseURL(existing.CatalogID, baseURL); err != nil {
		return Result{}, err
	}
	if req.ClearAPIKey && existing.CatalogID != openAICompatibleProviderID {
		return Result{}, service.Detail(service.ErrInvalidInput, "only openai-compatible providers may clear api_key")
	}
	if existing.CatalogID != openAICompatibleProviderID && existing.ApiKey == "" && req.APIKey == "" {
		return Result{}, service.Detail(service.ErrInvalidInput, "api_key is required")
	}
	if req.IsEnabled != nil && !*req.IsEnabled && existing.IsEnabled {
		inUse, err := q.HasProviderLiveAssignments(ctx, existing.ID)
		if err != nil {
			return Result{}, err
		}
		if inUse {
			return Result{}, service.Detail(service.ErrConflict, "provider is assigned as a system default, agent override, or model slot")
		}
	}

	params := dbq.UpdateProviderParams{
		ID:          pgtype.UUID{Bytes: id, Valid: true},
		DisplayName: req.DisplayName,
		Slug:        req.Slug,
		BaseUrl:     req.BaseURL,
	}
	if req.ClearAPIKey {
		params.UpdateApiKey = true
		params.ApiKey = ""
	} else if req.APIKey != "" {
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
	row, err := q.UpdateProvider(ctx, params)
	if err != nil {
		if isProviderSlugViolation(err) {
			return Result{}, service.Detail(service.ErrConflict, "provider slug already exists for provider_id")
		}
		s.logger.Error("update provider failed", zap.Error(err))
		return Result{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Result{}, err
	}
	return Result{Row: row}, nil
}

func (s *Service) ListModels(ctx context.Context, p authz.Principal, id uuid.UUID) ([]dbq.ProviderModel, error) {
	if err := s.authorize(ctx, p); err != nil {
		return nil, err
	}
	q := dbq.New(s.db.Pool())
	rowID := pgtype.UUID{Bytes: id, Valid: true}
	provider, err := q.GetProviderByID(ctx, rowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, service.ErrNotFound
		}
		return nil, err
	}
	if provider.CatalogID != openAICompatibleProviderID {
		return nil, service.Detail(service.ErrInvalidInput, "provider does not support endpoint-specific models")
	}
	models, err := q.ListProviderModels(ctx, rowID)
	if err != nil {
		s.logger.Error("list provider models failed", zap.Error(err))
		return nil, err
	}
	return models, nil
}

func (s *Service) ReplaceModels(ctx context.Context, p authz.Principal, id uuid.UUID, models []Model) ([]dbq.ProviderModel, error) {
	if err := s.authorize(ctx, p); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(models))
	for i := range models {
		models[i].ModelID = strings.TrimSpace(models[i].ModelID)
		models[i].DisplayName = strings.TrimSpace(models[i].DisplayName)
		switch {
		case models[i].ModelID == "":
			return nil, service.Detail(service.ErrInvalidInput, "models[%d].model_id is required", i)
		case len(models[i].ModelID) > 512:
			return nil, service.Detail(service.ErrInvalidInput, "models[%d].model_id is too long", i)
		case models[i].DisplayName == "":
			return nil, service.Detail(service.ErrInvalidInput, "models[%d].display_name is required", i)
		case models[i].ContextLimit <= 0:
			return nil, service.Detail(service.ErrInvalidInput, "models[%d].context_limit must be positive", i)
		case models[i].OutputLimit <= 0:
			return nil, service.Detail(service.ErrInvalidInput, "models[%d].output_limit must be positive", i)
		}
		if _, ok := seen[models[i].ModelID]; ok {
			return nil, service.Detail(service.ErrInvalidInput, "duplicate model_id %q", models[i].ModelID)
		}
		seen[models[i].ModelID] = struct{}{}
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ModelID < models[j].ModelID })

	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	rowID := pgtype.UUID{Bytes: id, Valid: true}
	provider, err := q.GetProviderByIDForUpdate(ctx, rowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, service.ErrNotFound
		}
		return nil, err
	}
	if provider.CatalogID != openAICompatibleProviderID {
		return nil, service.Detail(service.ErrInvalidInput, "provider does not support endpoint-specific models")
	}
	existing, err := q.ListProviderModels(ctx, rowID)
	if err != nil {
		return nil, err
	}
	replacement := make(map[string]Model, len(models))
	for _, model := range models {
		replacement[model.ModelID] = model
	}
	for _, old := range existing {
		model, found := replacement[old.ModelID]
		downgraded := found && (old.ToolCall && !model.ToolCall ||
			old.Reasoning && !model.Reasoning || old.Vision && !model.Vision ||
			old.StructuredOutputs && !model.StructuredOutputs ||
			model.ContextLimit < old.ContextLimit || model.OutputLimit < old.OutputLimit)
		if found && !downgraded {
			continue
		}
		referenced, err := q.IsProviderModelReferenced(ctx, dbq.IsProviderModelReferencedParams{
			CatalogID: rowID,
			Model:     old.ModelID,
		})
		if err != nil {
			return nil, err
		}
		if referenced {
			return nil, service.Detail(service.ErrConflict, "model %q is referenced and cannot be removed or downgraded", old.ModelID)
		}
	}
	if err := q.DeleteProviderModels(ctx, rowID); err != nil {
		return nil, err
	}
	out := make([]dbq.ProviderModel, 0, len(models))
	for _, model := range models {
		row, err := q.CreateProviderModel(ctx, dbq.CreateProviderModelParams{
			ConfiguredProviderID: rowID,
			ModelID:              model.ModelID, DisplayName: model.DisplayName,
			ToolCall: model.ToolCall, Reasoning: model.Reasoning, Vision: model.Vision,
			ContextLimit: model.ContextLimit, OutputLimit: model.OutputLimit,
			StructuredOutputs: model.StructuredOutputs,
			IncludeUsage:      model.IncludeUsage,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) DiscoverModels(ctx context.Context, p authz.Principal, id uuid.UUID) ([]ModelCandidate, error) {
	if err := s.authorize(ctx, p); err != nil {
		return nil, err
	}
	q := dbq.New(s.db.Pool())
	provider, err := q.GetProviderByID(ctx, pgtype.UUID{Bytes: id, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, service.ErrNotFound
		}
		return nil, err
	}
	if provider.CatalogID != openAICompatibleProviderID {
		return nil, service.Detail(service.ErrInvalidInput, "provider does not support model discovery")
	}
	apiKey := ""
	if provider.ApiKey != "" {
		apiKey, err = s.enc.Get(ctx, "provider/"+provider.ID.String()+"/api_key", provider.ApiKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt API key: %w", err)
		}
	}
	models, err := discoverModels(ctx, s.http, provider.BaseUrl, apiKey)
	if errors.Is(err, networkpolicy.ErrDisallowedURL) {
		return nil, service.Detail(service.ErrInvalidInput, "base_url is blocked by the configured HTTP network policy; allow its resolved private CIDR to enable discovery")
	}
	return models, err
}

func discoverModels(ctx context.Context, client *http.Client, baseURL, apiKey string) ([]ModelCandidate, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/models"
	u.RawQuery = ""
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discover models: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("discover models: endpoint returned HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxDiscoveryResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("discover models: read response: %w", err)
	}
	if len(raw) > maxDiscoveryResponseBytes {
		return nil, errors.New("discover models: response is too large")
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("discover models: invalid response: %w", err)
	}
	if len(payload.Data) > maxDiscoveredModels {
		return nil, errors.New("discover models: too many models")
	}
	seen := make(map[string]struct{}, len(payload.Data))
	out := make([]ModelCandidate, 0, len(payload.Data))
	for _, item := range payload.Data {
		id := strings.TrimSpace(item.ID)
		if id == "" || len(id) > 512 {
			return nil, errors.New("discover models: response contains an invalid model ID")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, ModelCandidate{ModelID: id})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModelID < out[j].ModelID })
	return out, nil
}

func validateSlug(slug string) error {
	if len(slug) == 0 || len(slug) > 63 || !providerSlugPattern.MatchString(slug) {
		return service.Detail(service.ErrInvalidInput, "slug must be 1-63 characters of strict kebab-case")
	}
	return nil
}

func validateProviderBaseURL(providerID, raw string) error {
	if providerID != openAICompatibleProviderID {
		return nil
	}
	if strings.TrimSpace(raw) == "" {
		return service.Detail(service.ErrInvalidInput, "base_url is required for openai-compatible")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return service.Detail(service.ErrInvalidInput, "base_url must be an absolute http or https URL without userinfo, query, or fragment")
	}
	return nil
}

func isProviderSlugViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "providers_provider_id_slug_key"
}

func (s *Service) Delete(ctx context.Context, p authz.Principal, id uuid.UUID) error {
	if err := s.authorize(ctx, p); err != nil {
		return err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(s.db.Pool()).WithTx(tx)
	rowID := pgtype.UUID{Bytes: id, Valid: true}
	if _, err := q.GetProviderByIDForUpdate(ctx, rowID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return service.ErrNotFound
		}
		return err
	}
	referenced, err := q.IsProviderReferenced(ctx, rowID)
	if err != nil {
		return err
	}
	if referenced {
		return service.Detail(service.ErrConflict, "provider is referenced by grants, defaults, agent overrides, or model slots")
	}
	if err := q.DeleteProvider(ctx, rowID); err != nil {
		s.logger.Error("delete provider failed", zap.Error(err))
		return err
	}
	return tx.Commit(ctx)
}
