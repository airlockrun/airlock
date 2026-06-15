package convert

import (
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	passkeyssvc "github.com/airlockrun/airlock/service/passkeys"
)

// PasskeyToProto maps a service passkey DTO to its wire type.
func PasskeyToProto(p passkeyssvc.Passkey) *airlockv1.Passkey {
	return &airlockv1.Passkey{
		Id:             p.ID.String(),
		FriendlyName:   p.FriendlyName,
		CreatedAt:      PgTimestampToProto(p.CreatedAt),
		LastUsedAt:     PgTimestampToProto(p.LastUsedAt),
		BackupEligible: p.BackupEligible,
	}
}
