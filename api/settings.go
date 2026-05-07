package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/secrets"
	"github.com/jackc/pgx/v5/pgtype"
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

	// Each default slot is a (provider FK, bare model name) pair. Both
	// halves must be present together or both absent — empty + invalid
	// FK ⇄ no default configured for this capability.
	pairs := []struct {
		name      string
		modelName string
		fkRaw     string
	}{
		{"default_build", in.DefaultBuildModel, in.DefaultBuildProviderId},
		{"default_exec", in.DefaultExecModel, in.DefaultExecProviderId},
		{"default_stt", in.DefaultSttModel, in.DefaultSttProviderId},
		{"default_vision", in.DefaultVisionModel, in.DefaultVisionProviderId},
		{"default_tts", in.DefaultTtsModel, in.DefaultTtsProviderId},
		{"default_image_gen", in.DefaultImageGenModel, in.DefaultImageGenProviderId},
		{"default_embedding", in.DefaultEmbeddingModel, in.DefaultEmbeddingProviderId},
		{"default_search", in.DefaultSearchModel, in.DefaultSearchProviderId},
	}
	parsedFKs := make(map[string]pgtype.UUID, len(pairs))
	for _, p := range pairs {
		fk, err := parseOptionalProviderID(p.fkRaw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid "+p.name+"_provider_id: "+err.Error())
			return
		}
		// Search is provider-scoped, not model-scoped: the runtime picks
		// the search backend by overlay capability on the provider row,
		// not by a stored model name. So default_search_model is always
		// empty by design — only the FK matters. Other slots must move
		// both halves together (set or unset).
		if p.name != "default_search" && (p.modelName != "") != fk.Valid {
			writeError(w, http.StatusBadRequest, p.name+"_model and "+p.name+"_provider_id must be set or unset together")
			return
		}
		parsedFKs[p.name] = fk
	}

	q := dbq.New(h.db.Pool())
	settings, err := q.UpdateSystemSettings(r.Context(), dbq.UpdateSystemSettingsParams{
		PublicUrl:                  in.PublicUrl,
		AgentDomain:                in.AgentDomain,
		DefaultBuildProviderID:     parsedFKs["default_build"],
		DefaultBuildModel:          in.DefaultBuildModel,
		DefaultExecProviderID:      parsedFKs["default_exec"],
		DefaultExecModel:           in.DefaultExecModel,
		DefaultSttProviderID:       parsedFKs["default_stt"],
		DefaultSttModel:            in.DefaultSttModel,
		DefaultVisionProviderID:    parsedFKs["default_vision"],
		DefaultVisionModel:         in.DefaultVisionModel,
		DefaultTtsProviderID:       parsedFKs["default_tts"],
		DefaultTtsModel:            in.DefaultTtsModel,
		DefaultImageGenProviderID:  parsedFKs["default_image_gen"],
		DefaultImageGenModel:       in.DefaultImageGenModel,
		DefaultEmbeddingProviderID: parsedFKs["default_embedding"],
		DefaultEmbeddingModel:      in.DefaultEmbeddingModel,
		DefaultSearchProviderID:    parsedFKs["default_search"],
		DefaultSearchModel:         in.DefaultSearchModel,
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
		PublicUrl:                  s.PublicUrl,
		AgentDomain:                s.AgentDomain,
		DefaultBuildModel:          s.DefaultBuildModel,
		DefaultExecModel:           s.DefaultExecModel,
		DefaultSttModel:            s.DefaultSttModel,
		DefaultVisionModel:         s.DefaultVisionModel,
		DefaultTtsModel:            s.DefaultTtsModel,
		DefaultImageGenModel:       s.DefaultImageGenModel,
		DefaultEmbeddingModel:      s.DefaultEmbeddingModel,
		DefaultSearchModel:         s.DefaultSearchModel,
		DefaultBuildProviderId:     convert.PgUUIDToString(s.DefaultBuildProviderID),
		DefaultExecProviderId:      convert.PgUUIDToString(s.DefaultExecProviderID),
		DefaultSttProviderId:       convert.PgUUIDToString(s.DefaultSttProviderID),
		DefaultVisionProviderId:    convert.PgUUIDToString(s.DefaultVisionProviderID),
		DefaultTtsProviderId:       convert.PgUUIDToString(s.DefaultTtsProviderID),
		DefaultImageGenProviderId:  convert.PgUUIDToString(s.DefaultImageGenProviderID),
		DefaultEmbeddingProviderId: convert.PgUUIDToString(s.DefaultEmbeddingProviderID),
		DefaultSearchProviderId:    convert.PgUUIDToString(s.DefaultSearchProviderID),
	}
}
