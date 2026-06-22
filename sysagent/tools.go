package sysagent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// destructiveTools lists every tool that mutates state and therefore
// triggers the confirmation halt in the gated executor. Reads are
// never destructive; every mutation is — including additive ones like
// add_sibling and add_agent_member (they grant new capabilities).
//
// Update this set whenever a new mutating tool lands. Code-review
// rule: if a tool's name starts with create_/update_/delete_/set_/
// trigger_/rollback_/cancel_/rotate_/unpin_/fire_/revoke_/clear_/
// add_/remove_/connect_/disconnect_, it should be in this set.
var destructiveTools = map[string]struct{}{
	"create_agent":              {},
	"update_agent":              {},
	"delete_agent":              {},
	"set_agent_lifecycle":       {},
	"trigger_agent_upgrade":     {},
	"rollback_agent":            {},
	"cancel_build":              {},
	"fire_schedule":             {},
	"connect_git":               {},
	"disconnect_git":            {},
	"delete_git_credential":     {},
	"create_tg_bot":             {},
	"update_bridge":             {},
	"delete_bridge":             {},
	"revoke_connection":         {},
	"revoke_mcp_credential":     {},
	"revoke_mcp_oauth_app":      {},
	"clear_env_var":             {},
	"rotate_exec_keypair":       {},
	"unpin_exec_host_key":       {},
	"cancel_run":                {},
	"add_sibling":               {},
	"update_sibling_max_access": {},
	"remove_sibling":            {},
	"set_agent_sharing":         {},
	"add_agent_member":          {},
	"remove_agent_member":       {},
}

// isDestructiveTool reports whether a tool name requires confirmation
// before execution. See destructiveTools.
func isDestructiveTool(name string) bool {
	_, ok := destructiveTools[name]
	return ok
}

// tenantAxisTools maps each tool to the authz.Action it would
// trigger when invoked. Only tenant-axis tools matter for the
// registration-time filter (Tools whose policy entry is AxisTenant
// and which the caller's tenant role doesn't satisfy get dropped
// from the catalogue entirely — agent-axis tools stay since the
// caller might still be admin of SOME agent).
//
// Agent-axis tools and "no policy" tools (whoami, deep links) are
// absent from this map → always registered.
var tenantAxisTools = map[string]authz.Action{
	"create_agent":  authz.TenantAgentCreate,
	"create_tg_bot": authz.TenantBridgeCreate,
	"update_bridge": authz.TenantBridgeCreate,
	"delete_bridge": authz.TenantBridgeCreate,
}

// buildToolSet returns the tool catalogue filtered to what the
// principal could possibly execute. Tenant-axis tools are dropped
// when the caller's tenant role doesn't satisfy the action's
// requirement; agent-axis tools are kept (the model self-selects
// per agent based on the `your_access` hint in list_agents output).
//
// The principal is needed only for the static filter; per-call
// agent-level authorization happens inside each service method via
// authz.Authorize.
func (s *Service) buildToolSet(p authz.Principal) tool.Set {
	set := tool.Set{}
	for _, t := range s.allTools() {
		if act, ok := tenantAxisTools[t.Name]; ok {
			if !p.TenantRole.AtLeast(authz.RequiredTenantRole(act)) {
				continue
			}
		}
		set.Add(t)
	}
	return set
}

// allTools returns the full unfiltered tool catalogue. Split by
// category across tools_*.go files; this is the single registration
// point. New tools land here and in destructiveTools/tenantAxisTools
// as appropriate.
func (s *Service) allTools() []tool.Tool {
	out := []tool.Tool{}
	out = append(out, s.selfTools()...)
	out = append(out, s.agentReadTools()...)
	out = append(out, s.agentMutateTools()...)
	out = append(out, s.bridgeTools()...)
	out = append(out, s.connectionTools()...)
	out = append(out, s.envExecTools()...)
	out = append(out, s.runTools()...)
	out = append(out, s.siblingMemberTools()...)
	out = append(out, s.deepLinkTools()...)
	return out
}

// --- shared input shapes ---

// agentSlugInput is the canonical "this tool targets one agent"
// envelope. Tools that need additional parameters embed it.
type agentSlugInput struct {
	Agent string `json:"agent" jsonschema:"required,description=The agent's slug (or UUID)."`
}

// --- shared helpers used by every tool body ---

// resolveAgent looks up an agent by slug-or-UUID and returns its
// row (so tools can pass agent.ID into service methods).
//
// service.ResolveAgent doesn't gate — it's a pure lookup. The
// service method we're about to call will gate via Authorize.
// resolveAgent's role is "the LLM gave us a slug; turn it into an
// id" and surface ErrNotFound through the standard sentinel path.
func (s *Service) resolveAgent(ctx context.Context, slug string) (dbq.Agent, error) {
	if slug == "" {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "agent is required")
	}
	a, err := service.ResolveAgent(ctx, dbq.New(s.db.Pool()), slug)
	if err != nil {
		return dbq.Agent{}, service.Detail(service.ErrNotFound, "agent %q not found", slug)
	}
	return a, nil
}

// resolveUUID parses a UUID string into a uuid.UUID, surfacing a
// uniform ErrInvalidInput on parse failure with the offending field
// name.
func resolveUUID(field, raw string) (uuid.UUID, error) {
	if raw == "" {
		return uuid.Nil, service.Detail(service.ErrInvalidInput, "%s is required", field)
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, service.Detail(service.ErrInvalidInput, "invalid %s: %s", field, raw)
	}
	return id, nil
}

// effectiveAccess wraps authz.EffectiveAgentAccess for callers that
// only need the level (whoami, the your_access augmentation
// fallback). Returns AccessPublic for a non-member caller.
func effectiveAccess(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID) string {
	return string(p.EffectiveAgentAccess(ctx, q, agentID))
}

// jsonBytes is a defensive marshal that never returns an error from
// a tool body — if marshal fails (shouldn't, for service return
// types) it falls back to "null" so the LLM at least sees something
// parseable.
func jsonBytes(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// Compile-time witness that we import auth for the principal layer
// — keeps the import non-dead while individual tool files reference
// it (or don't) depending on what they need.
var _ = auth.Role("")
var _ = fmt.Sprintf
