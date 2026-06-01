package convert

import (
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	connsvc "github.com/airlockrun/airlock/service/connections"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EnvVarToProto maps the connections service EnvVar DTO to the
// wire EnvVarInfo. Value is non-empty only when !is_secret AND
// configured (the service enforces this).
func EnvVarToProto(e connsvc.EnvVar) *airlockv1.EnvVarInfo {
	out := &airlockv1.EnvVarInfo{
		Slug:         e.Slug,
		Description:  e.Description,
		IsSecret:     e.IsSecret,
		Configured:   e.Configured,
		DefaultValue: e.DefaultValue,
		Pattern:      e.Pattern,
		Value:        e.Value,
	}
	if !e.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(e.UpdatedAt)
	}
	return out
}
