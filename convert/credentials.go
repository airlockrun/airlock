package convert

import (
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	connsvc "github.com/airlockrun/airlock/service/connections"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SetupCountsToProto packs the aggregate setup-completeness
// counters into the wire SetupCountsInfo.
func SetupCountsToProto(c connsvc.SetupCounts) *airlockv1.SetupCountsInfo {
	return &airlockv1.SetupCountsInfo{
		Connections: c.Connections,
		McpServers:  c.MCPServers,
		EnvVars:     c.EnvVars,
	}
}

// TestCredentialResultToProto packs the credential-probe outcome
// into the wire TestCredentialResponse.
func TestCredentialResultToProto(r connsvc.TestResult) *airlockv1.TestCredentialResponse {
	return &airlockv1.TestCredentialResponse{
		Success:    r.Success,
		StatusCode: r.StatusCode,
		Message:    r.Message,
	}
}

// CredentialStatusToProto packs a connections.Status into the wire
// CredentialStatusResponse.
func CredentialStatusToProto(st connsvc.Status) *airlockv1.CredentialStatusResponse {
	resp := &airlockv1.CredentialStatusResponse{
		Slug:       st.Slug,
		Name:       st.Name,
		AuthMode:   st.AuthMode,
		Authorized: st.Authorized,
	}
	if !st.TokenExpiresAt.IsZero() {
		resp.TokenExpiresAt = timestamppb.New(st.TokenExpiresAt)
	}
	return resp
}
