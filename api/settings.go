package api

import (
	"context"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/secrets"
	settingssvc "github.com/airlockrun/airlock/service/settings"
)

type settingsHandler struct {
	svc                *settingssvc.Service
	encryptor          secrets.Store
	managerBotUsername func() string // live username from the running manager bot poller; "" when stopped
	validateManagerBot func(ctx context.Context, token string) (username string, canManage bool, err error)
	managerBotReload   func(ctx context.Context) error
	managerBotScope    string
}

// settingsHandlerDeps bundles the bits the settings handler needs
// from the wider startup graph. ManagerBot* are nil when the
// manager-bot feature isn't wired in (e.g. tests); the handler
// surfaces "not configured" semantically in that case.
type settingsHandlerDeps struct {
	Svc                *settingssvc.Service
	Encryptor          secrets.Store
	ManagerBotUsername func() string
	ValidateManagerBot func(ctx context.Context, token string) (username string, canManage bool, err error)
	ManagerBotReload   func(ctx context.Context) error
	ManagerBotScope    string
}

func newSettingsHandler(d settingsHandlerDeps) *settingsHandler {
	if d.Svc == nil {
		panic("settingsHandler: svc is required")
	}
	h := &settingsHandler{
		svc:                d.Svc,
		encryptor:          d.Encryptor,
		managerBotUsername: d.ManagerBotUsername,
		validateManagerBot: d.ValidateManagerBot,
		managerBotReload:   d.ManagerBotReload,
		managerBotScope:    d.ManagerBotScope,
	}
	if h.managerBotUsername == nil {
		h.managerBotUsername = func() string { return "" }
	}
	return h
}

func (h *settingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	row, err := h.svc.Get(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to load system settings")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.GetSystemSettingsResponse{
		Settings: convert.SystemSettingsToProto(row, h.managerBotUsername()),
	})
}

// UpdateManagerBot validates a new Telegram manager-bot token and,
// on success, persists it + asks the poller to reload. An empty
// token disables the feature.
func (h *settingsHandler) UpdateManagerBot(w http.ResponseWriter, r *http.Request) {
	if h.encryptor == nil || h.validateManagerBot == nil {
		writeError(w, http.StatusServiceUnavailable, "manager bot feature is not wired")
		return
	}
	var req airlockv1.UpdateTelegramManagerBotRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	status, err := h.svc.UpdateManagerBotToken(
		r.Context(),
		principalFromRequest(r),
		req.GetToken(),
		h.encryptor.Put,
		h.validateManagerBot,
		h.managerBotReload,
		h.managerBotScope,
	)
	if err != nil {
		writeServiceError(w, err, "failed to update manager bot token")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.UpdateTelegramManagerBotResponse{
		Configured: status.Configured,
		Username:   status.Username,
		Error:      status.Error,
	})
}

func (h *settingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req airlockv1.UpdateSystemSettingsRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	in := req.GetSettings()
	if in == nil {
		writeError(w, http.StatusBadRequest, "settings is required")
		return
	}
	// Search's model field is empty by design — the runtime selects the
	// search backend from the provider row's overlay capability, not from
	// a stored model name. Every other slot must set or unset both halves
	// together; the service enforces that via SlotUpdate.ModelRequired.
	slots := []settingssvc.SlotUpdate{
		{Name: "default_build", Model: in.DefaultBuildModel, ProviderIDRaw: in.DefaultBuildProviderId, ModelRequired: true},
		{Name: "default_exec", Model: in.DefaultExecModel, ProviderIDRaw: in.DefaultExecProviderId, ModelRequired: true},
		{Name: "default_stt", Model: in.DefaultSttModel, ProviderIDRaw: in.DefaultSttProviderId, ModelRequired: true},
		{Name: "default_vision", Model: in.DefaultVisionModel, ProviderIDRaw: in.DefaultVisionProviderId, ModelRequired: true},
		{Name: "default_tts", Model: in.DefaultTtsModel, ProviderIDRaw: in.DefaultTtsProviderId, ModelRequired: true},
		{Name: "default_image_gen", Model: in.DefaultImageGenModel, ProviderIDRaw: in.DefaultImageGenProviderId, ModelRequired: true},
		{Name: "default_embedding", Model: in.DefaultEmbeddingModel, ProviderIDRaw: in.DefaultEmbeddingProviderId, ModelRequired: true},
		{Name: "default_search", Model: in.DefaultSearchModel, ProviderIDRaw: in.DefaultSearchProviderId, ModelRequired: false},
	}
	row, err := h.svc.Update(r.Context(), principalFromRequest(r), settingssvc.UpdateRequest{Slots: slots})
	if err != nil {
		writeServiceError(w, err, "failed to update system settings")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.UpdateSystemSettingsResponse{
		Settings: convert.SystemSettingsToProto(row, h.managerBotUsername()),
	})
}
