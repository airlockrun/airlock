package db

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/db/dbtest"
	"github.com/google/uuid"
)

// testURL is the DSN of the ephemeral database provisioned in TestMain.
// Empty when no database is available.
var testURL string

func TestMain(m *testing.M) {
	url, _, release, ok := dbtest.Setup(context.Background(), RunMigrations)
	if !ok {
		os.Exit(m.Run()) // no DB available; integration tests skip individually
	}
	testURL = url
	code := m.Run()
	release()
	os.Exit(code)
}

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	if testURL == "" {
		t.Skip("no test database (Docker unavailable)")
	}
	return testURL
}

func TestDBConnectAndPing(t *testing.T) {
	url := testDatabaseURL(t)
	ctx := context.Background()

	db := New(ctx, url)
	defer db.Close()

	err := db.Pool().Ping(ctx)
	if err != nil {
		t.Fatalf("ping failed: %v", err)
	}
}

func TestRunMigrations(t *testing.T) {
	// Migrations already ran in TestMain. Just verify they're idempotent.
	url := testDatabaseURL(t)
	if err := RunMigrations(url); err != nil {
		t.Fatalf("RunMigrations() failed: %v", err)
	}
}

func TestOAuthCredentialScopeVerificationConstraint(t *testing.T) {
	database := New(t.Context(), testDatabaseURL(t))
	defer database.Close()
	q := dbq.New(database.Pool())
	suffix := uuid.NewString()[:8]
	user, err := q.CreateUser(t.Context(), dbq.CreateUserParams{
		Email: "scope-constraint-" + suffix + "@example.com", DisplayName: "Scope Constraint", TenantRole: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := q.CreateAgent(t.Context(), dbq.CreateAgentParams{
		Name: "Scope Constraint", Slug: "scope-constraint-" + suffix, OwnerPrincipalID: user.ID, Config: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := q.UpsertConnection(t.Context(), dbq.UpsertConnectionParams{
		AgentID: agent.ID, Slug: "oauth", Name: "OAuth", DisplayName: "OAuth", AuthMode: "oauth",
		AuthInjection: []byte("{}"), Config: []byte("{}"), AuthParams: []byte("{}"), Headers: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := q.UpsertMCPServer(t.Context(), dbq.UpsertMCPServerParams{
		AgentID: agent.ID, Slug: "oauth", Name: "OAuth MCP", DisplayName: "OAuth MCP", AuthMode: "oauth", AuthInjection: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for table, id := range map[string]any{"connections": connection.ID, "agent_mcp_servers": server.ID} {
		if _, err := database.Pool().Exec(t.Context(), "UPDATE "+table+" SET access_token_ref='token', scopes_verified=false WHERE id=$1", id); err == nil {
			t.Errorf("%s accepted OAuth credentials without verified scopes", table)
		}
		if _, err := database.Pool().Exec(t.Context(), "UPDATE "+table+" SET access_token_ref='token', scopes_verified=true WHERE id=$1", id); err != nil {
			t.Errorf("%s rejected OAuth credentials with verified scopes: %v", table, err)
		}
	}
}

func TestResourceLifecycleSchemaAndQueryContract(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var migrationFiles []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") {
			migrationFiles = append(migrationFiles, entry.Name())
		}
	}
	if len(migrationFiles) != 1 || migrationFiles[0] != "001_schema.sql" {
		t.Fatalf("schema baseline migrations = %v, want [001_schema.sql]", migrationFiles)
	}
	contents, err := os.ReadFile("migrations/001_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	schema := string(contents)
	table := func(name string) string {
		t.Helper()
		start := strings.Index(schema, "CREATE TABLE public."+name+" (")
		if start < 0 {
			t.Fatalf("schema is missing table %s", name)
		}
		end := strings.Index(schema[start:], "\n);")
		if end < 0 {
			t.Fatalf("schema has no end for table %s", name)
		}
		return schema[start : start+end]
	}
	for _, name := range []string{"connections", "agent_mcp_servers"} {
		definition := table(name)
		for _, column := range []string{
			"display_name text NOT NULL", "lifecycle text NOT NULL",
			"granted_scopes text NOT NULL", "scopes_verified boolean NOT NULL",
			"authorization_revision bigint NOT NULL", "provisional_need_id uuid",
			"pending_client_id text NOT NULL", "pending_client_secret text NOT NULL",
		} {
			if count := strings.Count(definition, column); count != 1 {
				t.Errorf("%s must define %q exactly once; got %d", name, column, count)
			}
		}
	}
	if count := strings.Count(table("agent_exec_endpoints"), "display_name text NOT NULL"); count != 1 {
		t.Errorf("agent_exec_endpoints must define display_name exactly once; got %d", count)
	}
	for _, column := range []string{
		"need_id uuid NOT NULL", "requested_scopes text NOT NULL",
		"authorization_revision bigint NOT NULL", "expected_prior_resource_id uuid",
		"uses_pending_client boolean NOT NULL",
	} {
		if count := strings.Count(table("oauth_states"), column); count != 1 {
			t.Errorf("oauth_states must define %q exactly once; got %d", column, count)
		}
	}
	for _, required := range []string{
		"connections_provisional_need_owner_key UNIQUE (provisional_need_id, owner_principal_id)",
		"agent_mcp_servers_provisional_need_owner_key UNIQUE (provisional_need_id, owner_principal_id)",
		"connections_provisional_need_id_fkey FOREIGN KEY (provisional_need_id) REFERENCES public.agent_resource_needs(id) ON DELETE CASCADE",
		"agent_mcp_servers_provisional_need_id_fkey FOREIGN KEY (provisional_need_id) REFERENCES public.agent_resource_needs(id) ON DELETE CASCADE",
		"oauth_states_need_id_fkey FOREIGN KEY (need_id) REFERENCES public.agent_resource_needs(id) ON DELETE CASCADE",
		"connections_lifecycle_check", "agent_mcp_servers_lifecycle_check",
		"connections_display_name_check", "agent_mcp_servers_display_name_check", "agent_exec_endpoints_display_name_check",
		"connections_oauth_scopes_verified_check", "agent_mcp_servers_oauth_scopes_verified_check",
	} {
		if count := strings.Count(schema, required); count != 1 {
			t.Errorf("schema must contain %q exactly once; got %d", required, count)
		}
	}
	cleanup, err := os.ReadFile("queries/oauth_states.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cleanup), "FOR UPDATE SKIP LOCKED") || !strings.Contains(string(cleanup), "updated_at <") {
		t.Error("provisional cleanup is not lock-safe and based on authorization activity")
	}
	needs, err := os.ReadFile("queries/resource_needs.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"LockQualifyingConnectionBindings", "LockQualifyingMCPBindings", "LockConnectionBindings", "LockMCPBindings", "LockExecBindings"} {
		start := strings.Index(string(needs), "-- name: "+query)
		if start < 0 {
			t.Errorf("resource-needs queries are missing %s", query)
			continue
		}
		end := strings.Index(string(needs)[start+1:], "-- name:")
		section := string(needs)[start:]
		if end >= 0 {
			section = string(needs)[start : start+1+end]
		}
		if !strings.Contains(section, "ORDER BY") || !strings.Contains(section, "FOR UPDATE") {
			t.Errorf("%s must lock in deterministic order", query)
		}
	}
}
