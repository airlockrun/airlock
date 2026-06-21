package convert

import (
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	memberssvc "github.com/airlockrun/airlock/service/members"
	"github.com/jackc/pgx/v5/pgtype"
)

// MemberToProto maps the members service DTO to the wire
// AgentMemberInfo.
func MemberToProto(m memberssvc.Member) *airlockv1.AgentMemberInfo {
	return &airlockv1.AgentMemberInfo{
		UserId:      m.GranteeID.String(),
		Kind:        m.Kind,
		Email:       m.Email,
		DisplayName: m.DisplayName,
		Role:        m.Role,
		CreatedAt:   PgTimestampToProto(pgtype.Timestamptz{Time: m.CreatedAt, Valid: !m.CreatedAt.IsZero()}),
	}
}
