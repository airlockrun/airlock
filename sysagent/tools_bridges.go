package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	"github.com/airlockrun/goai/tool"
)

// bridgeTools wires the tenant-axis bridge tools (every mutator gates
// on TenantBridgeCreate; the registration-time filter in tools.go
// drops them for non-managers). Bridges aren't per-agent — they're
// tenant-scoped resources optionally bound to one agent.
//
// NOTE: secrets are never accepted in chat. Bridge tokens carry the
// bot's auth and must NOT be settable from sysagent; create_bridge
// here is intentionally absent from the rest of the SDK. The plan's
// inventory lists create_bridge as a tool, but the platform token is
// a hard secret the operator must paste in the Bridges page. We omit
// the create/update mutators that would need a token.
func (s *Service) bridgeTools() []tool.Tool {
	return []tool.Tool{
		s.toolListBridges(),
		s.toolDeleteBridge(),
		s.toolUpdateBridge(),
	}
}

// --- list_bridges ---

func (s *Service) toolListBridges() tool.Tool {
	return tool.New("list_bridges").
		Description(`List bridges the caller can see: system bridges for everyone; agent-bound bridges restricted to agent members. Each row carries the bridge config and (when set) owner info.`).
		SchemaFromStruct(struct{}{}).
		Execute(func(ctx context.Context, _ json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			p := principalFromCtx(ctx)
			rows, err := s.bridges.List(ctx, p)
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.BridgeInfo, len(rows))
			for i, item := range rows {
				out[i] = convert.BridgeListItemToProto(item)
			}
			return okResult(out)
		}).
		Build()
}

// --- update_bridge ---

type updateBridgeInput struct {
	BridgeID                   string `json:"bridge_id" jsonschema:"required,description=Bridge UUID."`
	AgentID                    string `json:"agent_id,omitempty" jsonschema:"description=Rebind to this agent UUID. Empty string means rebind to system / orphan state."`
	AllowPublicDMs             *bool  `json:"allow_public_dms,omitempty"`
	PublicSessionTTLSeconds    *int32 `json:"public_session_ttl_seconds,omitempty"`
	PublicSessionMode          string `json:"public_session_mode,omitempty"`
	PublicPromptTimeoutSeconds *int32 `json:"public_prompt_timeout_seconds,omitempty"`
}

func (s *Service) toolUpdateBridge() tool.Tool {
	return tool.New("update_bridge").
		Description(`Rebind a bridge to another agent and/or update its public-DM settings. All settings are optional — omit to leave alone. Requires admin-or-creator of the target bridge.`).
		SchemaFromStruct(updateBridgeInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in updateBridgeInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			bridgeID, err := resolveUUID("bridge_id", in.BridgeID)
			if err != nil {
				return errResult(err), nil
			}
			var settings *bridgessvc.SettingsUpdate
			if in.AllowPublicDMs != nil || in.PublicSessionTTLSeconds != nil ||
				in.PublicSessionMode != "" || in.PublicPromptTimeoutSeconds != nil {
				su := bridgessvc.SettingsUpdate{}
				if in.AllowPublicDMs != nil {
					su.AllowPublicDMs = *in.AllowPublicDMs
				}
				if in.PublicSessionTTLSeconds != nil {
					su.PublicSessionTTLSeconds = *in.PublicSessionTTLSeconds
				}
				if in.PublicPromptTimeoutSeconds != nil {
					su.PublicPromptTimeoutSeconds = *in.PublicPromptTimeoutSeconds
				}
				su.PublicSessionMode = in.PublicSessionMode
				settings = &su
			}
			p := principalFromCtx(ctx)
			res, err := s.bridges.Update(ctx, p, bridgeID, bridgessvc.UpdateRequest{
				AgentID:  in.AgentID,
				Settings: settings,
			})
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.BridgeResultToProto(res))
		}).
		Build()
}

// --- delete_bridge ---

type bridgeIDInput struct {
	BridgeID string `json:"bridge_id" jsonschema:"required,description=Bridge UUID."`
}

func (s *Service) toolDeleteBridge() tool.Tool {
	return tool.New("delete_bridge").
		Description(`Delete a bridge (irreversible — stops its poller and removes the row). Requires admin-or-creator.`).
		SchemaFromStruct(bridgeIDInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in bridgeIDInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			id, err := resolveUUID("bridge_id", in.BridgeID)
			if err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			if err := s.bridges.Delete(ctx, p, id); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "deleted", "bridge_id": id.String()})
		}).
		Build()
}
