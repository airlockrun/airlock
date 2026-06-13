package convert

import (
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	siblingssvc "github.com/airlockrun/airlock/service/siblings"
	"github.com/jackc/pgx/v5/pgtype"
)

// SiblingToProto maps the siblings service Sibling DTO to the wire
// SiblingInfo.
func SiblingToProto(s siblingssvc.Sibling) *airlockv1.SiblingInfo {
	return &airlockv1.SiblingInfo{
		Id:                s.ID.String(),
		Slug:              s.Slug,
		Name:              s.Name,
		Description:       s.Description,
		AllowNonMemberMcp: s.AllowNonMemberMcp,
		AllowPublicMcp:    s.AllowPublicMcp,
		CreatedAt:         PgTimestampToProto(pgtype.Timestamptz{Time: s.CreatedAt, Valid: !s.CreatedAt.IsZero()}),
	}
}

// AddableSiblingToProto maps the siblings service Addable DTO to
// the wire AddableSiblingInfo.
func AddableSiblingToProto(a siblingssvc.Addable) *airlockv1.AddableSiblingInfo {
	return &airlockv1.AddableSiblingInfo{
		Id:                a.ID.String(),
		Slug:              a.Slug,
		Name:              a.Name,
		Description:       a.Description,
		AllowNonMemberMcp: a.AllowNonMemberMcp,
		IsMember:          a.IsMember,
	}
}

// A2ASettingsToProto maps the per-agent MCP-exposure DTO to the
// wire A2ASettings.
func A2ASettingsToProto(s siblingssvc.A2ASettings) *airlockv1.A2ASettings {
	return &airlockv1.A2ASettings{
		AllowNonMemberMcp: s.AllowNonMemberMcp,
		AllowPublicMcp:    s.AllowPublicMcp,
	}
}
