package convert

import (
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	userssvc "github.com/airlockrun/airlock/service/users"
)

// UserSummaryToProto maps the users Summary DTO to the wire
// UserSummary. The tenant_role hint rides as a non-proto detail —
// the slim UserSummary message intentionally carries only id +
// email + display_name; callers that need the role use User
// (UserDetailToProto).
func UserSummaryToProto(u userssvc.Summary) *airlockv1.UserSummary {
	return &airlockv1.UserSummary{
		Id:          u.ID.String(),
		Email:       u.Email,
		DisplayName: u.DisplayName,
	}
}

// UserDetailToProto packs the users service Detail DTO into the wire
// User proto. Distinct from UserToProto, which maps a raw dbq.User
// row — the service DTO carries the same fields but with stricter
// types (uuid.UUID vs pgtype.UUID, string vs pgtype.Text).
func UserDetailToProto(d userssvc.Detail) *airlockv1.User {
	return &airlockv1.User{
		Id:                 d.ID.String(),
		Email:              d.Email,
		DisplayName:        d.DisplayName,
		TenantRole:         TenantRoleStringToProto(d.TenantRole),
		OidcSub:            d.OIDCSub,
		CreatedAt:          PgTimestampToProto(d.CreatedAt),
		UpdatedAt:          PgTimestampToProto(d.UpdatedAt),
		MustChangePassword: d.MustChangePassword,
	}
}
