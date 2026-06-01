package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	settingssvc "github.com/airlockrun/airlock/service/settings"
)

type settingsHandler struct {
	svc *settingssvc.Service
}

func newSettingsHandler(svc *settingssvc.Service) *settingsHandler {
	if svc == nil {
		panic("settingsHandler: svc is required")
	}
	return &settingsHandler{svc: svc}
}

func (h *settingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	row, err := h.svc.Get(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to load system settings")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.GetSystemSettingsResponse{
		Settings: convert.SystemSettingsToProto(row),
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
		Settings: convert.SystemSettingsToProto(row),
	})
}
