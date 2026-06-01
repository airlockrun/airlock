package sysagent

import "testing"

// TestIsDestructiveTool — every mutating tool must be in the destructive
// set so the gated executor routes it through Sol's PermissionManager;
// every read-only tool must NOT be, or the LLM would have to ask the
// operator to approve list_agents.
func TestIsDestructiveTool(t *testing.T) {
	destructive := []string{
		"create_agent",
		"update_agent",
		"delete_agent",
		"set_agent_lifecycle",
		"trigger_agent_upgrade",
		"rollback_agent",
		"cancel_build",
		"fire_cron",
		"connect_git",
		"disconnect_git",
		"delete_git_credential",
		"update_agent_models",
		"update_bridge",
		"delete_bridge",
		"revoke_connection",
		"revoke_mcp_credential",
		"revoke_mcp_oauth_app",
		"clear_env_var",
		"rotate_exec_keypair",
		"unpin_exec_host_key",
		"cancel_run",
		"add_sibling",
		"remove_sibling",
		"set_agent_sharing",
		"add_agent_member",
		"remove_agent_member",
	}
	for _, name := range destructive {
		if !isDestructiveTool(name) {
			t.Errorf("expected %q to be destructive (gated)", name)
		}
	}

	// Read-only / link-only / introspection tools — must NOT be gated.
	// A confirmation prompt on list_agents would shred operator
	// ergonomics; the audit log is what we rely on instead.
	nonDestructive := []string{
		"whoami",
		"list_users",
		"list_agents",
		"get_agent",
		"list_webhooks",
		"list_crons",
		"list_agent_declared_tools",
		"list_builds",
		"get_build",
		"get_git_config",
		"list_git_credentials",
		"get_agent_models",
		"list_available_models",
		"list_bridges",
		"list_connections",
		"get_connection_status",
		"connection_setup_status",
		"test_connection",
		"list_mcp_servers",
		"get_mcp_credential_status",
		"test_mcp_credential",
		"list_env_vars",
		"list_exec_endpoints",
		"test_exec_endpoint",
		"list_runs",
		"get_run",
		"get_run_logs",
		"list_siblings",
		"list_addable_siblings",
		"get_agent_sharing",
		"list_agent_members",
		"open_agent_details",
		"open_user_settings",
	}
	for _, name := range nonDestructive {
		if isDestructiveTool(name) {
			t.Errorf("%q must NOT be destructive (no operator approval needed for reads)", name)
		}
	}
}

// TestTenantAxisToolsMapping pins the tenant-axis filter so the
// registration-time drop in buildToolSet stays in sync with the
// policy table. A tool not in this map (most of the catalogue) is
// agent-axis or unrestricted; one in it is omitted entirely from
// the catalogue when the caller's tenant role doesn't satisfy the
// action's requirement.
func TestTenantAxisToolsMapping(t *testing.T) {
	if len(tenantAxisTools) == 0 {
		t.Fatalf("tenantAxisTools must not be empty")
	}
	for name, action := range tenantAxisTools {
		if action == "" {
			t.Errorf("tenant-axis tool %q mapped to empty action", name)
		}
	}
	// Sanity checks for the specific tools the catalogue documents as
	// tenant-axis. If new ones land, add a row here AND in policy.go.
	if _, ok := tenantAxisTools["create_agent"]; !ok {
		t.Errorf("create_agent must be tenant-axis (gated on TenantAgentCreate)")
	}
}
