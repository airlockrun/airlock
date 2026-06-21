package sysagent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	managedbotssvc "github.com/airlockrun/airlock/service/managedbots"
	"github.com/airlockrun/airlock/sysagent/agentview"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
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
		s.toolCreateTgBot(),
	}
}

// --- create_tg_bot ---

type createTgBotInput struct {
	Agent string `json:"agent" jsonschema:"required,description=Agent slug (or UUID) to bind the new Telegram bot to."`
	Name  string `json:"name,omitempty" jsonschema:"description=Display name for the new bot; pre-fills the Telegram bot name."`
}

func (s *Service) toolCreateTgBot() tool.Tool {
	return tool.New("create_tg_bot").
		Description(`Start creating a Telegram bot bound to an agent through the manager-bot deep link. Returns a t.me link the operator opens in Telegram to finish setup; the resulting bot becomes an agent-bound bridge. Errors if no Telegram manager bot is configured. Requires manager-or-admin tenant role and agent-admin on the target agent.`).
		SchemaFromStruct(createTgBotInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in createTgBotInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			out, err := s.managedbots.CreateSession(ctx, p, managedbotssvc.CreateSessionRequest{
				AgentID:       uuid.UUID(a.ID.Bytes),
				SuggestedName: in.Name,
			})
			if err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{
				"status":     "Open this link in Telegram to finish creating the bot",
				"deep_link":  out.DeepLink,
				"expires_at": out.Expires.Format(time.RFC3339),
			})
		}).
		Build()
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
			// id stays — bridge_id is the handle for update_bridge/delete_bridge.
			return okResult(agentview.StripEach(out, "created_at", "updated_at", "last_polled_at"))
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
			return okResult(agentview.Strip(convert.BridgeResultToProto(res), "created_at", "updated_at", "last_polled_at"))
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
