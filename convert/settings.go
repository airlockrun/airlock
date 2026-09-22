package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

// SystemSettingsToProto maps the persisted tenant-wide settings to their wire
// shape for the activation and settings views.
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
		CodegenMaxSteps:            s.CodegenMaxSteps,
		CodegenMaxInputTokens:      s.CodegenMaxInputTokens,
		UiLocale:                   s.UiLocale,
	}
}
