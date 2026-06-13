package sysagent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/airlockrun/goai/tool"
)

// deepLinkTools wires the two link-only tools the LLM uses to direct
// the operator into the UI for any flow that would require pasting a
// secret in chat (API keys, OAuth client_secret, MCP tokens, env-var
// values, exec-endpoint host config, git PATs). These do NOT delegate
// to a service — they format a URL off Service.publicURL and return.
//
// No authz gate; the URL is public knowledge (it's just the SPA's
// route). Authorization happens when the user actually clicks it and
// the SPA loads with their JWT.
func (s *Service) deepLinkTools() []tool.Tool {
	return []tool.Tool{
		s.toolOpenAgentDetails(),
		s.toolOpenUserSettings(),
	}
}

// --- open_agent_details ---

type openAgentDetailsInput struct {
	Agent string `json:"agent" jsonschema:"required,description=Agent slug or UUID — the link uses this to open the right agent's details page."`
}

func (s *Service) toolOpenAgentDetails() tool.Tool {
	return tool.New("open_agent_details").
		Description(`Return a URL to the agent's details page. Use this whenever a flow needs the operator to paste a secret (API key, OAuth client_secret, MCP token, env-var value, exec-endpoint host config) — tell the operator in prose which tab to open ("open the Connections tab and paste the key there"). Don't fabricate section anchors; the frontend tab names are not part of this contract.`).
		SchemaFromStruct(openAgentDetailsInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in openAgentDetailsInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			url := strings.TrimRight(s.publicURL, "/") + "/agents/" + a.Slug
			return okResult(map[string]string{
				"url":   url,
				"agent": a.Slug,
				"hint":  "Tell the operator which tab to open in prose — the URL is the entry point, not a deep link to a section.",
			})
		}).
		Build()
}

// --- open_user_settings ---

func (s *Service) toolOpenUserSettings() tool.Tool {
	return tool.New("open_user_settings").
		Description(`Return a URL to the operator's settings page. Covers git credentials, profile, and other user-scoped config that would need a secret. Use this when the operator needs to add a git PAT before connect_git can proceed.`).
		SchemaFromStruct(struct{}{}).
		Execute(func(ctx context.Context, _ json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			url := strings.TrimRight(s.publicURL, "/") + "/settings"
			return okResult(map[string]string{
				"url":  url,
				"hint": "Tell the operator in prose what to do once the page is open.",
			})
		}).
		Build()
}
