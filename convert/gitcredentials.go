package convert

import (
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	gitcredssvc "github.com/airlockrun/airlock/service/gitcredentials"
)

// GitCredToProto maps the gitcredentials service DTO to the wire
// GitCredential. The service DTO already omits the token bytes; this
// converter is a pure field projection.
func GitCredToProto(c gitcredssvc.Credential) *airlockv1.GitCredential {
	return &airlockv1.GitCredential{
		Id:              c.ID.String(),
		UserId:          c.UserID.String(),
		Type:            c.Type,
		Name:            c.Name,
		GithubInstallId: c.GithubInstallID,
		CreatedAt:       PgTimestampToProto(c.CreatedAt),
		LastUsedAt:      PgTimestampToProto(c.LastUsedAt),
	}
}
