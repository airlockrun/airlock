// Package settings owns the single-row system_settings table: the
// tenant-wide default (provider FK, bare model name) pairs the
// agent-create flow prefills from. Read is open to any authenticated
// user (the agent-create form needs it); write is admin-only. Both
// gates run through authz.Authorize.
package settings

import (
	"context"
	"strings"

	"github.com/airlockrun/airlock/apihelpers"
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

func New(d *db.DB, logger *zap.Logger) *Service {
	if d == nil {
		panic("settings: db is required")
	}
	if logger == nil {
		panic("settings: logger is required")
	}
	return &Service{db: d, logger: logger}
}

// SlotUpdate is one (provider FK, bare model name) pair the operator
// is editing for a single capability. The raw FK string is parsed
// inside Update so the handler doesn't need to know which empty/uuid
// rules apply per capability.
type SlotUpdate struct {
	Name          string // logical key: "default_build", "default_exec", …
	Model         string
	ProviderIDRaw string
	ModelRequired bool // when false, an empty model paired with an FK is allowed (e.g. default_search)
}

// UpdateRequest carries every capability slot. The handler builds it
// from the inbound proto; the service does the empty/FK validation +
// per-slot model-required rule.
type UpdateRequest struct {
	Slots []SlotUpdate
}

func (s *Service) Get(ctx context.Context, p authz.Principal) (dbq.SystemSetting, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSettingsView, uuid.Nil); err != nil {
		return dbq.SystemSetting{}, err
	}
	row, err := q.GetSystemSettings(ctx)
	if err != nil {
		s.logger.Error("get system settings failed", zap.Error(err))
		return dbq.SystemSetting{}, err
	}
	return row, nil
}

// ManagerBotStatus is the system-settings view the UI surfaces on the
// Telegram Manager Bot settings card: the encrypted-token presence
// flag, the resolved username from the poller's last successful
// getMe (empty when un-validated), and the last validation error
// (empty when healthy).
type ManagerBotStatus struct {
	Configured bool
	Username   string
	Error      string
}

// UpdateManagerBotToken validates the raw token via getMe + the
// can_manage_bots gate (caller supplies the validator), encrypts the
// token, persists the ciphertext, and asks the poller to reload. On
// validation failure the error string is persisted (and returned)
// without changing the stored token — so a typo doesn't blow away a
// working configuration.
func (s *Service) UpdateManagerBotToken(
	ctx context.Context,
	p authz.Principal,
	rawToken string,
	encrypt func(ctx context.Context, scope, plaintext string) (string, error),
	validate func(ctx context.Context, token string) (username string, canManage bool, err error),
	reload func(ctx context.Context) error,
	tokenScope string,
) (ManagerBotStatus, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantManagerBotConfig, uuid.Nil); err != nil {
		return ManagerBotStatus{}, err
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		// Empty token = "disable manager bot." Clear the stored
		// ciphertext + error, reload (which Stops the poller).
		if _, err := q.UpdateTelegramManagerBotToken(ctx, dbq.UpdateTelegramManagerBotTokenParams{
			TokenRef:  "",
			ErrorText: "",
		}); err != nil {
			s.logger.Error("clear manager bot token failed", zap.Error(err))
			return ManagerBotStatus{}, err
		}
		if reload != nil {
			_ = reload(ctx)
		}
		return ManagerBotStatus{}, nil
	}

	username, canManage, verr := validate(ctx, rawToken)
	if verr != nil {
		errText := "getMe: " + verr.Error()
		if _, err := q.UpdateTelegramManagerBotToken(ctx, dbq.UpdateTelegramManagerBotTokenParams{
			TokenRef:  "", // refuse to persist an invalid token
			ErrorText: errText,
		}); err != nil {
			s.logger.Error("record manager bot validation error failed", zap.Error(err))
			return ManagerBotStatus{}, err
		}
		return ManagerBotStatus{}, service.Detail(service.ErrInvalidInput, "%s", errText)
	}
	if !canManage {
		errText := "bot @" + username + " does not have can_manage_bots enabled in BotFather"
		_, _ = q.UpdateTelegramManagerBotToken(ctx, dbq.UpdateTelegramManagerBotTokenParams{
			TokenRef:  "",
			ErrorText: errText,
		})
		return ManagerBotStatus{Username: username}, service.Detail(service.ErrInvalidInput, "%s", errText)
	}

	enc, err := encrypt(ctx, tokenScope, rawToken)
	if err != nil {
		s.logger.Error("encrypt manager bot token failed", zap.Error(err))
		return ManagerBotStatus{}, err
	}
	if _, err := q.UpdateTelegramManagerBotToken(ctx, dbq.UpdateTelegramManagerBotTokenParams{
		TokenRef:  enc,
		ErrorText: "",
	}); err != nil {
		s.logger.Error("persist manager bot token failed", zap.Error(err))
		return ManagerBotStatus{}, err
	}
	if reload != nil {
		_ = reload(ctx)
	}
	return ManagerBotStatus{Configured: true, Username: username}, nil
}

// GetManagerBotStatus reads the current status row for the settings
// page. Authz: same as settings view.
func (s *Service) GetManagerBotStatus(ctx context.Context, p authz.Principal, runningUsername string) (ManagerBotStatus, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSettingsView, uuid.Nil); err != nil {
		return ManagerBotStatus{}, err
	}
	row, err := q.GetTelegramManagerBotStatus(ctx)
	if err != nil {
		return ManagerBotStatus{}, err
	}
	return ManagerBotStatus{
		Configured: row.TelegramManagerBotTokenRef != "",
		Username:   runningUsername,
		Error:      row.TelegramManagerBotError,
	}, nil
}

func (s *Service) Update(ctx context.Context, p authz.Principal, req UpdateRequest) (dbq.SystemSetting, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSettingsUpdate, uuid.Nil); err != nil {
		return dbq.SystemSetting{}, err
	}

	parsed := make(map[string]pgtype.UUID, len(req.Slots))
	models := make(map[string]string, len(req.Slots))
	for _, slot := range req.Slots {
		fk, err := apihelpers.ParseOptionalProviderID(slot.ProviderIDRaw)
		if err != nil {
			return dbq.SystemSetting{}, service.Detail(service.ErrInvalidInput, "invalid %s_provider_id: %v", slot.Name, err)
		}
		// A required-model slot must move both halves together: either set
		// or unset. Search is the exception — the runtime picks the search
		// backend off the provider's overlay capability, so the model
		// field stays empty by design.
		if slot.ModelRequired && (slot.Model != "") != fk.Valid {
			return dbq.SystemSetting{}, service.Detail(service.ErrInvalidInput,
				"%s_model and %s_provider_id must be set or unset together", slot.Name, slot.Name)
		}
		parsed[slot.Name] = fk
		models[slot.Name] = slot.Model
	}

	row, err := q.UpdateSystemSettings(ctx, dbq.UpdateSystemSettingsParams{
		DefaultBuildProviderID:     parsed["default_build"],
		DefaultBuildModel:          models["default_build"],
		DefaultExecProviderID:      parsed["default_exec"],
		DefaultExecModel:           models["default_exec"],
		DefaultSttProviderID:       parsed["default_stt"],
		DefaultSttModel:            models["default_stt"],
		DefaultVisionProviderID:    parsed["default_vision"],
		DefaultVisionModel:         models["default_vision"],
		DefaultTtsProviderID:       parsed["default_tts"],
		DefaultTtsModel:            models["default_tts"],
		DefaultImageGenProviderID:  parsed["default_image_gen"],
		DefaultImageGenModel:       models["default_image_gen"],
		DefaultEmbeddingProviderID: parsed["default_embedding"],
		DefaultEmbeddingModel:      models["default_embedding"],
		DefaultSearchProviderID:    parsed["default_search"],
		DefaultSearchModel:         models["default_search"],
	})
	if err != nil {
		s.logger.Error("update system settings failed", zap.Error(err))
		return dbq.SystemSetting{}, err
	}
	return row, nil
}
