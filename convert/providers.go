package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

// MaskAPIKey returns a masked version of an API key for display.
// Shows first 3 and last 4 characters: "sk-...key1".
// Keys shorter than 8 characters are fully masked.
func MaskAPIKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:3] + "..." + key[len(key)-4:]
}

// ProviderToProto converts a dbq.Provider to the proto type.
// The decryptedKey is used only for masking — the full key is never exposed.
func ProviderToProto(p dbq.Provider, decryptedKey string) *airlockv1.Provider {
	return &airlockv1.Provider{
		Id:           PgUUIDToString(p.ID),
		ProviderId:   p.ProviderID,
		DisplayName:  p.DisplayName,
		ApiKeyMasked: MaskAPIKey(decryptedKey),
		BaseUrl:      p.BaseUrl,
		IsEnabled:    p.IsEnabled,
		CreatedAt:    PgTimestampToProto(p.CreatedAt),
		UpdatedAt:    PgTimestampToProto(p.UpdatedAt),
	}
}
