package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/execproxy"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	execsvc "github.com/airlockrun/airlock/service/execendpoints"
)

// ExecEndpointTestToProto packs the exec-endpoint probe outcome
// into the wire ExecEndpointTestResult.
func ExecEndpointTestToProto(r execsvc.TestResult) *airlockv1.ExecEndpointTestResult {
	return &airlockv1.ExecEndpointTestResult{
		Ok:         r.OK,
		ExitCode:   int32(r.ExitCode),
		DurationMs: r.DurationMs,
		Stdout:     r.Stdout,
		Stderr:     r.Stderr,
		Error:      r.Error,
	}
}

// ExecEndpointRowToProto packs an AgentExecEndpoint row into the
// wire ExecEndpointInfo. Strips PrivateKeyRef (a secrets-store
// reference) and the full host-key blob; only the SHA256
// fingerprint is exposed so the operator can verify TOFU pinning
// without leaking the raw key material to clients or the LLM.
func ExecEndpointRowToProto(ep dbq.AgentExecEndpoint) *airlockv1.ExecEndpointInfo {
	out := &airlockv1.ExecEndpointInfo{
		Id:               PgUUIDToString(ep.ID),
		Slug:             ep.Slug,
		Description:      ep.Description,
		LlmHint:          ep.LlmHint,
		Access:           ep.Access,
		Transport:        ep.Transport.String,
		Host:             ep.Host.String,
		SshUser:          ep.SshUser.String,
		PublicKeyOpenssh: ep.PublicKeyOpenssh.String,
		PublicKeyComment: ep.PublicKeyComment.String,
		HostKeyPinnedAt:  PgTimestampToProto(ep.HostKeyPinnedAt),
		LastUsedAt:       PgTimestampToProto(ep.LastUsedAt),
	}
	if ep.Port.Valid {
		out.Port = ep.Port.Int32
	}
	if ep.HostKeyOpenssh.Valid && ep.HostKeyOpenssh.String != "" {
		out.HostKeyFingerprint = execproxy.HostKeyFingerprint(ep.HostKeyOpenssh.String)
	}
	return out
}

// ExecNeedRowToProto packs an agent's exec-endpoint need (joined to its bound
// resource, if any) into the wire ExecEndpointInfo. Id is the zero UUID for an
// unconfigured need; the agent's handle is the need Slug.
func ExecNeedRowToProto(ep dbq.ListExecNeedsByAgentRow) *airlockv1.ExecEndpointInfo {
	out := &airlockv1.ExecEndpointInfo{
		Id:               PgUUIDToString(ep.ExecID),
		Slug:             ep.Slug,
		Description:      ep.Description,
		LlmHint:          ep.LlmHint,
		Access:           ep.Access,
		Transport:        ep.Transport.String,
		Host:             ep.Host.String,
		SshUser:          ep.SshUser.String,
		PublicKeyOpenssh: ep.PublicKeyOpenssh.String,
		PublicKeyComment: ep.PublicKeyComment.String,
		HostKeyPinnedAt:  PgTimestampToProto(ep.HostKeyPinnedAt),
		LastUsedAt:       PgTimestampToProto(ep.LastUsedAt),
	}
	if ep.Port.Valid {
		out.Port = ep.Port.Int32
	}
	if ep.HostKeyOpenssh.Valid && ep.HostKeyOpenssh.String != "" {
		out.HostKeyFingerprint = execproxy.HostKeyFingerprint(ep.HostKeyOpenssh.String)
	}
	return out
}
