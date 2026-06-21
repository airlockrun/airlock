package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/sysagent/agentview"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// connectionTools wires the per-agent connection (OAuth/API-key) and
// MCP-server tools. Setters that would require pasting a secret in
// chat (SetAPIKey, SetOAuthApp, SetMCPToken, SetMCPOAuthApp,
// SetEnvVarValue) are deliberately NOT exposed — the operator gets a
// deep link to open_agent_details instead.
func (s *Service) connectionTools() []tool.Tool {
	return []tool.Tool{
		s.toolListConnections(),
		s.toolGetConnectionStatus(),
		s.toolConnectionSetupStatus(),
		s.toolRevokeConnection(),
		s.toolTestConnection(),
		s.toolListMCPServers(),
		s.toolGetMCPCredentialStatus(),
		s.toolRevokeMCPCredential(),
		s.toolTestMCPCredential(),
		s.toolRevokeMCPOAuthApp(),
	}
}

type agentSlugAndSlugInput struct {
	Agent string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	Slug  string `json:"slug" jsonschema:"required,description=Connection / MCP / env-var slug declared by the agent."`
}

// --- list_connections ---

func (s *Service) toolListConnections() tool.Tool {
	return tool.New("list_connections").
		Description(`List the agent's declared connections (OAuth + API-key) with kind, status (connected / disconnected / oauth_app_unconfigured / api_key_missing), and last-sync timestamp.`).
		SchemaFromStruct(agentSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			agentID := uuid.UUID(a.ID.Bytes)
			out, err := s.conns.ListConnections(ctx, p, agentID)
			if err != nil {
				return errResult(err), nil
			}
			conns := make([]*airlockv1.ConnectionInfo, len(out.Connections))
			for i, c := range out.Connections {
				conns[i] = convert.ConnectionDTOToProto(c, s.publicURL, agentID.String())
			}
			return okResult(map[string]any{
				"connections":        agentview.StripEach(conns, "id", "created_at", "updated_at", "token_expires_at"),
				"oauth_callback_url": out.OAuthCallbackURL,
			})
		}).
		Build()
}

// --- get_connection_status ---

func (s *Service) toolGetConnectionStatus() tool.Tool {
	return tool.New("get_connection_status").
		Description(`Return one connection's status (kind, configured/connected, last-sync, scopes when OAuth).`).
		SchemaFromStruct(agentSlugAndSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugAndSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			out, err := s.conns.CredentialStatus(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.CredentialStatusToProto(out))
		}).
		Build()
}

// --- connection_setup_status ---

func (s *Service) toolConnectionSetupStatus() tool.Tool {
	return tool.New("connection_setup_status").
		Description(`Return aggregate setup-completeness counts across all the agent's connections and MCP servers (configured / total). Use this to spot agents that need their operator to finish setup.`).
		SchemaFromStruct(agentSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			out, err := s.conns.SetupStatus(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.SetupCountsToProto(out))
		}).
		Build()
}

// --- revoke_connection ---

func (s *Service) toolRevokeConnection() tool.Tool {
	return tool.New("revoke_connection").
		Description(`Revoke a connection — drops its stored credential / OAuth tokens. The agent will need the operator to re-authorize it (use open_agent_details).`).
		SchemaFromStruct(agentSlugAndSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugAndSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			if err := s.conns.RevokeCredential(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "revoked", "agent": a.Slug, "slug": in.Slug})
		}).
		Build()
}

// --- test_connection ---

func (s *Service) toolTestConnection() tool.Tool {
	return tool.New("test_connection").
		Description(`Probe a connection using its current stored credential (no override key — that would require pasting a secret in chat). Returns {ok, status, message} so the operator knows whether the credential is healthy.`).
		SchemaFromStruct(agentSlugAndSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugAndSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			out, err := s.conns.TestCredential(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug, "")
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.TestCredentialResultToProto(out))
		}).
		Build()
}

// --- list_mcp_servers ---

func (s *Service) toolListMCPServers() tool.Tool {
	return tool.New("list_mcp_servers").
		Description(`List the agent's declared MCP servers (slug, URL, auth kind, status, tool count).`).
		SchemaFromStruct(agentSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			rows, err := s.conns.ListMCPServers(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.MCPServerInfo, len(rows))
			for i, m := range rows {
				out[i] = convert.MCPServerToProto(m, s.publicURL, uuid.UUID(a.ID.Bytes).String())
			}
			return okResult(agentview.StripEach(out, "id", "created_at", "updated_at"))
		}).
		Build()
}

// --- get_mcp_credential_status ---

func (s *Service) toolGetMCPCredentialStatus() tool.Tool {
	return tool.New("get_mcp_credential_status").
		Description(`Return one MCP server's credential status (configured/connected, scopes when OAuth).`).
		SchemaFromStruct(agentSlugAndSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugAndSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			out, err := s.conns.MCPCredentialStatus(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.MCPStatusToProto(out))
		}).
		Build()
}

// --- revoke_mcp_credential ---

func (s *Service) toolRevokeMCPCredential() tool.Tool {
	return tool.New("revoke_mcp_credential").
		Description(`Revoke an MCP server's credential (drops the stored token / OAuth grant). Operator will need to re-authorize via open_agent_details.`).
		SchemaFromStruct(agentSlugAndSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugAndSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			if err := s.conns.RevokeMCPCredential(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "revoked", "agent": a.Slug, "slug": in.Slug})
		}).
		Build()
}

// --- test_mcp_credential ---

func (s *Service) toolTestMCPCredential() tool.Tool {
	return tool.New("test_mcp_credential").
		Description(`Probe an MCP server using its current stored credential.`).
		SchemaFromStruct(agentSlugAndSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugAndSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			out, err := s.conns.TestMCPCredential(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug, "")
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.TestCredentialResultToProto(out))
		}).
		Build()
}

// --- revoke_mcp_oauth_app ---

func (s *Service) toolRevokeMCPOAuthApp() tool.Tool {
	return tool.New("revoke_mcp_oauth_app").
		Description(`Drop the stored OAuth app (client_id + client_secret) for an MCP server. Operator must re-register via open_agent_details before the server can re-authorize.`).
		SchemaFromStruct(agentSlugAndSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugAndSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			if err := s.conns.RevokeMCPOAuthApp(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "revoked", "agent": a.Slug, "slug": in.Slug})
		}).
		Build()
}
