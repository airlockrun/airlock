package authz

import (
	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
)

// Axis is the permission axis an action gates on. The two axes are
// independent (see airlock/CLAUDE.md "Permission Model"): agent access
// comes from agent_members, tenant role from the user record/JWT.
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
	AgentDelete       Action = "agent.delete"
	AgentLifecycle    Action = "agent.lifecycle" // stop / start / suspend
	AgentGit          Action = "agent.git"       // connect / disconnect / read git binding
	AgentRunView      Action = "agent.run.view"  // runs list / get / logs
	AgentMembersView  Action = "agent.members.view"
	AgentToolsView    Action = "agent.tools.view"
	AgentBuildsView   Action = "agent.builds.view"  // builds list / get
	AgentConversation Action = "agent.conversation" // create / list web conversations
	AgentModelsView   Action = "agent.models.view"

	// Agent axis — owner (AccessAdmin) required.
	AgentBuildManage   Action = "agent.build.manage" // upgrade / rollback / cancel build
	AgentMembersManage Action = "agent.members.manage"
	AgentWebhooksView  Action = "agent.webhooks.view"
	AgentCronsView     Action = "agent.crons.view"
	AgentCronFire      Action = "agent.cron.fire"
	AgentConnections   Action = "agent.connections"    // credentials / MCP / env-vars
	AgentExecEndpoints Action = "agent.exec_endpoints" // SSH exec-endpoint config
	AgentSiblings      Action = "agent.siblings"
	AgentModelsUpdate  Action = "agent.models.update"

	// Tenant axis.
	TenantBridgeCreate   Action = "tenant.bridge.create" // any bridge: manager+
	TenantBridgeSystem   Action = "tenant.bridge.system" // system (agent-less) bridge: admin
	TenantUserManage     Action = "tenant.user.manage"
	TenantProviderManage Action = "tenant.provider.manage"
	TenantSettingsUpdate Action = "tenant.settings.update"
)

// policy is the whole permission matrix. Authorize panics on a missing
// entry (fail loud) so a new action can't silently default to "allowed".
var policy = map[Action]Requirement{
	AgentGet:          {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentUpdate:       {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentDelete:       {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentLifecycle:    {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentGit:          {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentRunView:      {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentMembersView:  {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentToolsView:    {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentBuildsView:   {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentConversation: {Axis: AxisAgent, Agent: agentsdk.AccessUser},
	AgentModelsView:   {Axis: AxisAgent, Agent: agentsdk.AccessUser},

	AgentBuildManage:   {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentMembersManage: {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentWebhooksView:  {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentCronsView:     {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentCronFire:      {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentConnections:   {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentExecEndpoints: {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentSiblings:      {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},
	AgentModelsUpdate:  {Axis: AxisAgent, Agent: agentsdk.AccessAdmin},

	TenantBridgeCreate:   {Axis: AxisTenant, Tenant: auth.RoleManager},
	TenantBridgeSystem:   {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantUserManage:     {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantProviderManage: {Axis: AxisTenant, Tenant: auth.RoleAdmin},
	TenantSettingsUpdate: {Axis: AxisTenant, Tenant: auth.RoleAdmin},
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
