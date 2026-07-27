package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

// ProviderToProto converts a dbq.Provider to the proto type. The API key is
// never included — it's write-once and encrypted at rest; HasApiKey reports
// only whether a key is configured (the ciphertext column is non-empty).
func ProviderToProto(p dbq.Provider) *airlockv1.Provider {
	return &airlockv1.Provider{
		Id:          PgUUIDToString(p.ID),
		ProviderId:  p.CatalogID,
		Slug:        p.Slug,
		DisplayName: p.DisplayName,
		HasApiKey:   p.ApiKey != "",
		BaseUrl:     p.BaseUrl,
		IsEnabled:   p.IsEnabled,
		CreatedAt:   PgTimestampToProto(p.CreatedAt),
		UpdatedAt:   PgTimestampToProto(p.UpdatedAt),
	}
}

func ProviderModelToProto(m dbq.ProviderModel) *airlockv1.ProviderModel {
	return &airlockv1.ProviderModel{
		ModelId:           m.ModelID,
		DisplayName:       m.DisplayName,
		ToolCall:          m.ToolCall,
		Reasoning:         m.Reasoning,
		Vision:            m.Vision,
		ContextLimit:      m.ContextLimit,
		OutputLimit:       m.OutputLimit,
		StructuredOutputs: m.StructuredOutputs,
		IncludeUsage:      m.IncludeUsage,
		CreatedAt:         PgTimestampToProto(m.CreatedAt),
		UpdatedAt:         PgTimestampToProto(m.UpdatedAt),
	}
}
