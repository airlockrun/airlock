package authz

import (
	"sort"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
)

// Axis is the permission axis an action gates on. The two axes are
// independent (see airlock/CLAUDE.md "Permission Model"): agent access
// comes from agent_grants, tenant role from the user record/JWT.
type Axis int

const (
	AxisAgent  Axis = iota // requires a per-agent access level
	AxisTenant             // requires a tenant role
)

// Requirement is the minimum access an action needs. Exactly one of
// Agent/Tenant is meaningful, per Axis.
type Requirement struct {
	Axis   Axis
	Agent  agentsdk.Access // AxisAgent
	Tenant auth.Role       // AxisTenant
}

// Action names a gated operation. The policy map below is the single
// source of truth for "what level does this action require" — every
// surface authorizes by Action, never by a hardcoded level at the call
// site, so the two routes that can reach the same action can't drift.
type Action string

const (
	// Agent axis — member (AccessUser) suffices.
	AgentGet          Action = "agent.get"
	AgentUpdate       Action = "agent.update"
	AgentLifecycle    Action = "agent.lifecycle" // stop / start / suspend
	AgentGit          Action = "agent.git"       // connect / disconnect / read git binding
	AgentRunView      Action = "agent.run.view"  // runs list / get / logs
	AgentMembersView  Action = "agent.members.view"
	AgentToolsView    Action = "agent.tools.view"
	AgentBuildsView   Action = "agent.builds.view"  // builds list / get
	AgentConversation Action = "agent.conversation" // create / list web conversations
	AgentModelsView   Action = "agent.models.view"
	AgentClone        Action = "agent.clone" // fork this agent's code into a new agent (member of source; also needs TenantAgentClone)

	// Agent axis — owner (AccessAdmin) required.
	AgentDelete        Action = "agent.delete"
	AgentBuildManage   Action = "agent.build.manage" // upgrade / rollback / cancel build
	AgentMembersManage Action = "agent.members.manage"
	AgentWebhooksView  Action = "agent.webhooks.view"
	AgentSchedulesView Action = "agent.schedules.view"
	AgentScheduleFire  Action = "agent.schedule.fire"
	AgentConnections   Action = "agent.connections"    // credentials / MCP / env-vars
	AgentExecEndpoints Action = "agent.exec_endpoints" // SSH exec-endpoint config
	AgentSiblings      Action = "agent.siblings"
	AgentModelsUpdate  Action = "agent.models.update"

	// Tenant axis.
	TenantCatalogView         Action = "tenant.catalog.view"           // read providers/models/capabilities catalog: user+
	TenantUserView            Action = "tenant.user.view"              // read tenant user directory (id/email/display_name): user+
	TenantAgentCreate         Action = "tenant.agent.create"           // create an agent: manager+
	TenantAgentList           Action = "tenant.agent.list"             // list agents visible to the caller: user+
	TenantAgentListAll        Action = "tenant.agent.list_all"         // list every agent in the tenant: admin
	TenantAgentMembersSelfAdd Action = "tenant.agent.members.self_add" // escape: tenant admin adds self to an agent they're not yet a member of: admin
	TenantAgentLifecycleAny   Action = "tenant.agent.lifecycle_any"    // stop/start/suspend an agent the caller isn't a member of: admin
	TenantAgentDeleteAny      Action = "tenant.agent.delete_any"       // delete an agent the caller isn't a member of: admin
	TenantAgentClone          Action = "tenant.agent.clone"            // clone an agent (produces a new agent): manager+ (paired with AgentClone member gate)
	TenantAgentTransferAny    Action = "tenant.agent.transfer_any"     // transfer an agent the caller doesn't own: admin
	TenantBridgeList          Action = "tenant.bridge.list"            // list bridges visible to the caller: user+
	TenantBridgeListAll       Action = "tenant.bridge.list_all"        // list every bridge in the tenant: admin
	TenantBridgeCreate        Action = "tenant.bridge.create"          // any bridge: manager+
	TenantBridgeUpdateAny     Action = "tenant.bridge.update_any"      // edit a bridge the caller doesn't own: admin
	TenantBridgeDeleteAny     Action = "tenant.bridge.delete_any"      // delete a bridge the caller doesn't own: admin
	TenantBridgeSystem        Action = "tenant.bridge.system"          // system (agent-less) bridge: admin
	TenantManagerBotConfig    Action = "tenant.manager_bot.config"     // configure the Telegram-managed-bots manager bot token: admin
	TenantUserManage          Action = "tenant.user.manage"
	TenantProviderView        Action = "tenant.provider.view" // list configured providers (no secrets) for model selection: manager+
	TenantProviderManage      Action = "tenant.provider.manage"
	TenantSettingsView        Action = "tenant.settings.view" // read system defaults (agent-create prefill): user+
	TenantSettingsUpdate      Action = "tenant.settings.update"
	TenantIdentityManage      Action = "tenant.identity.manage"     // link / list / unlink caller's own platform identities: user+
	TenantIdentityManageAll   Action = "tenant.identity.manage_all" // list / unlink any user's platform identities: admin
	TenantSelfPasskeyManage   Action = "tenant.self.passkey.manage" // register / list / rename / delete the caller's own passkeys + set/remove own password: user+
	TenantGroupView           Action = "tenant.group.view"          // list groups + their grants: admin
	TenantModelGrantManage    Action = "tenant.model_grant.manage"  // grant/revoke which (provider, model) a group may use: admin
	TenantUsageView           Action = "tenant.usage.view"          // read the LLM spend ledger rollups (billing/usage): admin
)

// policy is the whole permission matrix. Authorize panics on a missing
// entry (fail loud) so a new action can't silently default to "allowed".
var policy = map[Action]Requirement{
	AgentGet:          {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentUpdate:       {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentLifecycle:    {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentGit:          {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentRunView:      {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentMembersView:  {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentToolsView:    {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentBuildsView:   {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentConversation: {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentModelsView:   {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentClone:        {Axis: AxisAgent, Agent: agentsdk.AccessUser},

	AgentDelete:        {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentBuildManage:   {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentMembersManage: {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentWebhooksView:  {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentSchedulesView: {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentScheduleFire:  {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentConnections:   {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentExecEndpoints: {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentSiblings:      {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentModelsUpdate:  {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},

	TenantCatalogView:         {Axis: AxisTenant, Tenant: auth.RoleUser},
	TenantUserView:            {Axis: AxisTenant, Tenant: auth.RoleUser},
	TenantAgentCreate:         {Axis: AxisTenant, Tenant: auth.RoleManager},
	TenantAgentList:           {Axis: AxisTenant, Tenant: auth.RoleUser},
	TenantAgentListAll:        {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantAgentMembersSelfAdd: {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantAgentLifecycleAny:   {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantAgentDeleteAny:      {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantAgentClone:          {Axis: AxisTenant, Tenant: auth.RoleManager},
	TenantAgentTransferAny:    {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantBridgeList:          {Axis: AxisTenant, Tenant: auth.RoleUser},
	TenantBridgeListAll:       {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantBridgeCreate:        {Axis: AxisTenant, Tenant: auth.RoleManager},
	TenantBridgeUpdateAny:     {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantBridgeDeleteAny:     {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantBridgeSystem:        {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantManagerBotConfig:    {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantUserManage:          {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantProviderView:        {Axis: AxisTenant, Tenant: auth.RoleManager},
	TenantProviderManage:      {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantSettingsView:        {Axis: AxisTenant, Tenant: auth.RoleUser},
	TenantSettingsUpdate:      {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantIdentityManage:      {Axis: AxisTenant, Tenant: auth.RoleUser},
	TenantIdentityManageAll:   {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantSelfPasskeyManage:   {Axis: AxisTenant, Tenant: auth.RoleUser},
	TenantGroupView:           {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantModelGrantManage:    {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantUsageView:           {Axis: AxisTenant, Tenant: auth.RoleAdmin},
}

// RequiredTenantRole returns the minimum tenant role for a tenant-axis
// action, so the router's RequireTenantRole middleware can source its
// level from the same policy table rather than a literal. Panics if the
// action is unknown or not tenant-axis (fail loud).
func RequiredTenantRole(a Action) auth.Role {
	req, ok := policy[a]
	if !ok {
		panic("authz: unknown action " + string(a))
	}
	if req.Axis != AxisTenant {
		panic("authz: not a tenant-axis action: " + string(a))
	}
	return req.Tenant
}

// GrantedTenantActions returns every tenant-axis Action that `role`
// satisfies, sorted lexicographically. The frontend consumes this via
// /api/v1/me to gate UI without duplicating the role ladder — `can(a)`
// becomes set membership, and adding a new Action surfaces in the UI
// purely through whatever can() call sites reference it.
//
// Agent-axis actions are deliberately excluded: their requirement
// depends on per-resource membership, not tenant role, and surface in
// the agent payload's `your_access` field instead.
func GrantedTenantActions(role auth.Role) []Action {
	var out []Action
	for a, req := range policy {
		if req.Axis != AxisTenant {
			continue
		}
		if role.AtLeast(req.Tenant) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
