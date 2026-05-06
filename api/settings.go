package api

import (
	"net/http"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/secrets"
	"go.uber.org/zap"
)

type settingsHandler struct {
	db        *db.DB
	encryptor secrets.Store
	logger    *zap.Logger
}

// Get returns the current system settings (admin only).
func (h *settingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	q := dbq.New(h.db.Pool())
	settings, err := q.GetSystemSettings(r.Context())
	if err != nil {
		h.logger.Error("get system settings failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.GetSystemSettingsResponse{
		Settings: settingsInfo(settings),
	})
}

// Update modifies system settings (admin only).
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

	q := dbq.New(h.db.Pool())
	settings, err := q.UpdateSystemSettings(r.Context(), dbq.UpdateSystemSettingsParams{
		PublicUrl:            in.PublicUrl,
		AgentDomain:          in.AgentDomain,
		DefaultBuildModel:    in.DefaultBuildModel,
		DefaultExecModel:     in.DefaultExecModel,
		DefaultSttModel:      in.DefaultSttModel,
		DefaultVisionModel:   in.DefaultVisionModel,
		DefaultTtsModel:      in.DefaultTtsModel,
		DefaultImageGenModel: in.DefaultImageGenModel,
		DefaultEmbeddingModel: in.DefaultEmbeddingModel,
		DefaultSearchModel:   in.DefaultSearchModel,
	})
	if err != nil {
		h.logger.Error("update system settings failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.UpdateSystemSettingsResponse{
		Settings: settingsInfo(settings),
	})
}

func settingsInfo(s dbq.SystemSetting) *airlockv1.SystemSettingsInfo {
	return &airlockv1.SystemSettingsInfo{
		PublicUrl:            s.PublicUrl,
		AgentDomain:          s.AgentDomain,
		DefaultBuildModel:    s.DefaultBuildModel,
		DefaultExecModel:     s.DefaultExecModel,
		DefaultSttModel:      s.DefaultSttModel,
		DefaultVisionModel:   s.DefaultVisionModel,
		DefaultTtsModel:      s.DefaultTtsModel,
		DefaultImageGenModel: s.DefaultImageGenModel,
		DefaultEmbeddingModel: s.DefaultEmbeddingModel,
		DefaultSearchModel:   s.DefaultSearchModel,
	}
}
