package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

// SystemSettingsToProto maps the persisted defaults row to its wire
// shape: the per-capability (provider FK, bare model name) pairs the
// agent-create flow prefills from and the settings page edits.
func SystemSettingsToProto(s dbq.SystemSetting) *airlockv1.SystemSettingsInfo {
	return &airlockv1.SystemSettingsInfo{
		DefaultBuildModel:          s.DefaultBuildModel,
		DefaultExecModel:           s.DefaultExecModel,
		DefaultSttModel:            s.DefaultSttModel,
		DefaultVisionModel:         s.DefaultVisionModel,
		DefaultTtsModel:            s.DefaultTtsModel,
		DefaultImageGenModel:       s.DefaultImageGenModel,
		DefaultEmbeddingModel:      s.DefaultEmbeddingModel,
		DefaultSearchModel:         s.DefaultSearchModel,
		DefaultBuildProviderId:     PgUUIDToString(s.DefaultBuildProviderID),
		DefaultExecProviderId:      PgUUIDToString(s.DefaultExecProviderID),
		DefaultSttProviderId:       PgUUIDToString(s.DefaultSttProviderID),
		DefaultVisionProviderId:    PgUUIDToString(s.DefaultVisionProviderID),
		DefaultTtsProviderId:       PgUUIDToString(s.DefaultTtsProviderID),
		DefaultImageGenProviderId:  PgUUIDToString(s.DefaultImageGenProviderID),
		DefaultEmbeddingProviderId: PgUUIDToString(s.DefaultEmbeddingProviderID),
		DefaultSearchProviderId:    PgUUIDToString(s.DefaultSearchProviderID),
	}
}
