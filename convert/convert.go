// Package convert provides dbq→proto conversion functions shared by api and realtime packages.
package convert

import (
	"encoding/json"

	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- Scalar helpers ---

func PgUUIDToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func PgTimestampToProto(t pgtype.Timestamptz) *timestamppb.Timestamp {
	if !t.Valid {
		return nil
	}
	return timestamppb.New(t.Time)
}

// --- Proto helpers ---

// AnyToStruct marshals an arbitrary Go value to a protobuf Struct via JSON round-trip.
func AnyToStruct(v any) *structpb.Struct {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	s, _ := structpb.NewStruct(m)
	return s
}

// AnyToListValue marshals an arbitrary Go slice to a protobuf ListValue via JSON round-trip.
func AnyToListValue(v any) *structpb.ListValue {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var items []any
	if err := json.Unmarshal(b, &items); err != nil {
		return nil
	}
	lv, _ := structpb.NewList(items)
	return lv
}

// --- Model converters ---

func TenantToProto(t dbq.Tenant) *airlockv1.Tenant {
	var settings *structpb.Struct
	if len(t.Settings) > 0 {
		settings = &structpb.Struct{}
		json.Unmarshal(t.Settings, settings)
	}
	return &airlockv1.Tenant{
		Id:        PgUUIDToString(t.ID),
		Name:      t.Name,
		Slug:      t.Slug,
		Settings:  settings,
		CreatedAt: PgTimestampToProto(t.CreatedAt),
		UpdatedAt: PgTimestampToProto(t.UpdatedAt),
	}
}

func tenantRoleToProto(s string) airlockv1.TenantRole {
	switch s {
	case "admin":
		return airlockv1.TenantRole_TENANT_ROLE_ADMIN
	case "manager":
		return airlockv1.TenantRole_TENANT_ROLE_MANAGER
	case "user":
		return airlockv1.TenantRole_TENANT_ROLE_USER
	default:
		return airlockv1.TenantRole_TENANT_ROLE_UNSPECIFIED
	}
}

func UserToProto(u dbq.User) *airlockv1.User {
	return &airlockv1.User{
		Id:                 PgUUIDToString(u.ID),
		Email:              u.Email,
		DisplayName:        u.DisplayName,
		TenantRole:         tenantRoleToProto(u.TenantRole),
		OidcSub:            u.OidcSub,
		CreatedAt:          PgTimestampToProto(u.CreatedAt),
		UpdatedAt:          PgTimestampToProto(u.UpdatedAt),
		MustChangePassword: u.MustChangePassword,
	}
}
