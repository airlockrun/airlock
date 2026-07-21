package db

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/db/dbtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pressly/goose/v3"
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

func TestResourceLifecycleMigrationAcceptsPrecedingReplicaInserts(t *testing.T) {
	database := New(t.Context(), testDatabaseURL(t))
	defer database.Close()
	q := dbq.New(database.Pool())
	suffix := uuid.NewString()[:8]
	user, err := q.CreateUser(t.Context(), dbq.CreateUserParams{Email: "compat-" + suffix + "@example.com", DisplayName: "Compat", TenantRole: "user"})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := q.CreateAgent(t.Context(), dbq.CreateAgentParams{Name: "Compat", Slug: "compat-" + suffix, OwnerPrincipalID: user.ID, Config: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}

	connID := uuid.New()
	_, err = database.Pool().Exec(t.Context(), `
		INSERT INTO connections (id, owner_principal_id, slug, name, description, llm_hint, access, auth_mode, auth_url, token_url, base_url, scopes, auth_injection, test_path, setup_instructions, config, client_id, client_secret, access_token_ref, refresh_token, auth_params, headers)
		VALUES ($1,$2,$3,'Compat connection','','','admin','oauth','https://provider.example/auth','https://provider.example/token','https://api.example','read','{}','','','{}','','','','','{}','{}')`,
		connID, user.ID, "compat-"+suffix)
	if err != nil {
		t.Fatalf("preceding connection insert: %v", err)
	}
	conn, err := q.GetConnectionByID(t.Context(), pgtype.UUID{Bytes: connID, Valid: true})
	if err != nil || conn.DisplayName != "Compat connection" || conn.Lifecycle != "active" || conn.AuthorizationRevision != 0 {
		t.Fatalf("derived connection fields: %+v, %v", conn, err)
	}

	mcpID := uuid.New()
	_, err = database.Pool().Exec(t.Context(), `
		INSERT INTO agent_mcp_servers (id, owner_principal_id, slug, name, access, url, auth_mode, auth_url, token_url, registration_endpoint, scopes, auth_injection, tool_schemas, client_id, client_secret, access_token_ref, refresh_token, server_instructions)
		VALUES ($1,$2,$3,'Compat MCP','admin','https://mcp.example','none','','','','','{}','[]','','','','','')`,
		mcpID, user.ID, "compat-mcp-"+suffix)
	if err != nil {
		t.Fatalf("preceding MCP insert: %v", err)
	}
	mcp, err := q.GetMCPServerByID(t.Context(), pgtype.UUID{Bytes: mcpID, Valid: true})
	if err != nil || mcp.DisplayName != "Compat MCP" || mcp.Lifecycle != "active" {
		t.Fatalf("derived MCP fields: %+v, %v", mcp, err)
	}

	execID := uuid.New()
	_, err = database.Pool().Exec(t.Context(), `
		INSERT INTO agent_exec_endpoints (id, owner_principal_id, slug, description, llm_hint, access)
		VALUES ($1,$2,$3,'Compat exec','','admin')`, execID, user.ID, "compat-exec-"+suffix)
	if err != nil {
		t.Fatalf("preceding exec insert: %v", err)
	}
	execEndpoint, err := q.GetExecEndpointByID(t.Context(), pgtype.UUID{Bytes: execID, Valid: true})
	if err != nil || execEndpoint.DisplayName != "compat-exec-"+suffix {
		t.Fatalf("derived exec display name: %+v, %v", execEndpoint, err)
	}

	if err := q.UpsertResourceNeed(t.Context(), dbq.UpsertResourceNeedParams{
		AgentID: agent.ID, Type: "connection", Slug: "oauth", Description: "OAuth", ExpectedScopes: "read", Spec: []byte("{}"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.BindConnectionNeed(t.Context(), dbq.BindConnectionNeedParams{AgentID: agent.ID, Slug: "oauth", ResourceID: pgtype.UUID{Bytes: connID, Valid: true}}); err != nil {
		t.Fatal(err)
	}
	stateToken := "compat-state-" + suffix
	_, err = database.Pool().Exec(t.Context(), `
		INSERT INTO oauth_states (state, agent_id, user_id, resource_id, slug, code_verifier, redirect_uri, expires_at, source_type)
		VALUES ($1,$2,$3,$4,'oauth','verifier','https://airlock.example/callback',$5,'connection')`,
		stateToken, agent.ID, user.ID, connID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("preceding OAuth state insert: %v", err)
	}
	state, err := q.GetOAuthState(t.Context(), stateToken)
	if err != nil || state.RequestedScopes != "read" || state.AuthorizationRevision != conn.AuthorizationRevision || state.NeedID.Bytes == [16]byte{} {
		t.Fatalf("mapped OAuth state: %+v, %v", state, err)
	}
}

func TestResourceLifecycleMigrationSafetyContract(t *testing.T) {
	contents, err := os.ReadFile("migrations/002_resource_oauth_lifecycle.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(contents)
	for _, required := range []string{
		"resource_lifecycle_insert_compat", "oauth_state_insert_compat",
		"UNIQUE (provisional_need_id, owner_principal_id)", "scopes_verified",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration is missing %q", required)
		}
	}
	if strings.Contains(sql, "DELETE FROM oauth_states;") {
		t.Error("migration destructively deletes all OAuth states")
	}
	if strings.Contains(sql, "SET scopes =") {
		t.Error("migration rewrites the rollback-visible declared scope column")
	}
	down := strings.Index(sql, "-- +goose Down")
	deleteConnection := strings.Index(sql, "DELETE FROM connections WHERE lifecycle = 'provisional'")
	deleteMCP := strings.Index(sql, "DELETE FROM agent_mcp_servers WHERE lifecycle = 'provisional'")
	dropLifecycle := -1
	if down >= 0 {
		if offset := strings.Index(sql[down:], "DROP COLUMN IF EXISTS lifecycle"); offset >= 0 {
			dropLifecycle = down + offset
		}
	}
	if down < 0 || deleteConnection < down || deleteMCP < down || dropLifecycle < down || deleteConnection > dropLifecycle || deleteMCP > dropLifecycle {
		t.Error("migration Down must delete provisional resources before dropping lifecycle metadata")
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

func TestResourceLifecycleMigrationUpgradeDataAndDownCleanup(t *testing.T) {
	url := testDatabaseURL(t)
	migrationDB, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationDB.Close()
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownToContext(t.Context(), migrationDB, "migrations", 1); err != nil {
		t.Fatalf("migrate down to 001: %v", err)
	}
	t.Cleanup(func() {
		restoreDB, err := sql.Open("postgres", url)
		if err != nil {
			t.Errorf("open migration cleanup database: %v", err)
			return
		}
		defer restoreDB.Close()
		if err := goose.UpToContext(context.Background(), restoreDB, "migrations", 2); err != nil {
			t.Errorf("restore migration 002: %v", err)
		}
	})

	database := New(t.Context(), url)
	q := dbq.New(database.Pool())
	suffix := uuid.NewString()[:8]
	user, err := q.CreateUser(t.Context(), dbq.CreateUserParams{
		Email: "upgrade-" + suffix + "@example.com", DisplayName: "Upgrade", TenantRole: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := q.CreateAgent(t.Context(), dbq.CreateAgentParams{
		Name: "Upgrade", Slug: "upgrade-" + suffix, OwnerPrincipalID: user.ID, Config: []byte("{}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	connectionID, mcpID, execID := uuid.New(), uuid.New(), uuid.New()
	if _, err := database.Pool().Exec(t.Context(), `
		INSERT INTO connections (id, owner_principal_id, slug, name, description, llm_hint, access, auth_mode, auth_url, token_url, base_url, scopes, auth_injection, test_path, setup_instructions, config, client_id, client_secret, access_token_ref, refresh_token, auth_params, headers)
		VALUES ($1,$2,$3,'Legacy connection','','','admin','oauth','https://provider.example/auth','https://provider.example/token','https://api.example','["write","read"]','{}','','','{}','','','legacy-access','','{}','{}')`,
		connectionID, user.ID, "legacy-connection-"+suffix); err != nil {
		t.Fatalf("seed legacy connection: %v", err)
	}
	if _, err := database.Pool().Exec(t.Context(), `
		INSERT INTO agent_mcp_servers (id, owner_principal_id, slug, name, access, url, auth_mode, auth_url, token_url, registration_endpoint, scopes, auth_injection, tool_schemas, client_id, client_secret, access_token_ref, refresh_token, server_instructions)
		VALUES ($1,$2,$3,'Legacy MCP','admin','https://mcp.example','oauth','https://provider.example/auth','https://provider.example/token','','write read','{}','[]','','','legacy-mcp-access','','')`,
		mcpID, user.ID, "legacy-mcp-"+suffix); err != nil {
		t.Fatalf("seed legacy MCP: %v", err)
	}
	if _, err := database.Pool().Exec(t.Context(), `
		INSERT INTO agent_exec_endpoints (id, owner_principal_id, slug, description, llm_hint, access)
		VALUES ($1,$2,$3,'Legacy exec','','admin')`, execID, user.ID, "legacy-exec-"+suffix); err != nil {
		t.Fatalf("seed legacy exec: %v", err)
	}
	needID := uuid.New()
	if _, err := database.Pool().Exec(t.Context(), `
		INSERT INTO agent_resource_needs (id, agent_id, type, slug, description, setup_instructions, expected_url, expected_scopes, spec, bound_connection_id)
		VALUES ($1,$2,'connection','documents','','','https://api.example','write read','{}',$3)`, needID, agent.ID, connectionID); err != nil {
		t.Fatalf("seed legacy binding: %v", err)
	}
	liveState, expiredState := "legacy-live-"+suffix, "legacy-expired-"+suffix
	for _, state := range []struct {
		token     string
		expiresAt time.Time
	}{{liveState, time.Now().Add(time.Hour)}, {expiredState, time.Now().Add(-time.Hour)}} {
		if _, err := database.Pool().Exec(t.Context(), `
			INSERT INTO oauth_states (state, agent_id, user_id, resource_id, slug, code_verifier, redirect_uri, expires_at, source_type)
			VALUES ($1,$2,$3,$4,'documents','verifier','https://airlock.example/callback',$5,'connection')`,
			state.token, agent.ID, user.ID, connectionID, state.expiresAt); err != nil {
			t.Fatalf("seed legacy OAuth state: %v", err)
		}
	}
	database.Close()

	if err := goose.UpToContext(t.Context(), migrationDB, "migrations", 2); err != nil {
		t.Fatalf("apply migration 002: %v", err)
	}
	database = New(t.Context(), url)
	defer database.Close()
	q = dbq.New(database.Pool())
	connection, err := q.GetConnectionByID(t.Context(), pgtype.UUID{Bytes: connectionID, Valid: true})
	if err != nil {
		t.Fatal(err)
	}
	if connection.DisplayName != "Legacy connection" || connection.Lifecycle != "active" || connection.GrantedScopes != "read write" || connection.ScopesVerified {
		t.Fatalf("connection backfill = %+v", connection)
	}
	mcpServer, err := q.GetMCPServerByID(t.Context(), pgtype.UUID{Bytes: mcpID, Valid: true})
	if err != nil {
		t.Fatal(err)
	}
	if mcpServer.DisplayName != "Legacy MCP" || mcpServer.Lifecycle != "active" || mcpServer.GrantedScopes != "read write" || mcpServer.ScopesVerified {
		t.Fatalf("MCP backfill = %+v", mcpServer)
	}
	execEndpoint, err := q.GetExecEndpointByID(t.Context(), pgtype.UUID{Bytes: execID, Valid: true})
	if err != nil || execEndpoint.DisplayName != "legacy-exec-"+suffix {
		t.Fatalf("exec display backfill = %+v err=%v", execEndpoint, err)
	}
	need, err := q.GetResourceNeed(t.Context(), dbq.GetResourceNeedParams{AgentID: agent.ID, Type: "connection", Slug: "documents"})
	if err != nil || !need.BoundConnectionID.Valid || uuid.UUID(need.BoundConnectionID.Bytes) != connectionID {
		t.Fatalf("binding after upgrade = %+v err=%v", need, err)
	}
	state, err := q.GetOAuthState(t.Context(), liveState)
	if err != nil || uuid.UUID(state.NeedID.Bytes) != needID || state.RequestedScopes != "read write" || state.AuthorizationRevision != 0 || !state.ExpectedPriorResourceID.Valid || uuid.UUID(state.ExpectedPriorResourceID.Bytes) != connectionID || state.UsesPendingClient {
		t.Fatalf("mapped OAuth state = %+v err=%v", state, err)
	}
	var expiredExists bool
	if err := database.Pool().QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM oauth_states WHERE state=$1)`, expiredState).Scan(&expiredExists); err != nil || expiredExists {
		t.Fatalf("expired OAuth state exists=%v err=%v", expiredExists, err)
	}

	provisionalConnection, provisionalMCP := uuid.New(), uuid.New()
	if _, err := database.Pool().Exec(t.Context(), `
		INSERT INTO connections (id, owner_principal_id, slug, name, description, llm_hint, access, auth_mode, auth_url, token_url, base_url, scopes, auth_injection, test_path, setup_instructions, config, client_id, client_secret, access_token_ref, refresh_token, auth_params, headers, lifecycle, provisional_need_id)
		VALUES ($1,$2,$3,'Provisional connection','','','admin','oauth','https://provider.example/auth','https://provider.example/token','https://api.example','read','{}','','','{}','','','','','{}','{}','provisional',$4)`,
		provisionalConnection, user.ID, "provisional-connection-"+suffix, needID); err != nil {
		t.Fatalf("seed provisional connection: %v", err)
	}
	if _, err := database.Pool().Exec(t.Context(), `
		INSERT INTO agent_mcp_servers (id, owner_principal_id, slug, name, access, url, auth_mode, auth_url, token_url, registration_endpoint, scopes, auth_injection, tool_schemas, client_id, client_secret, access_token_ref, refresh_token, server_instructions, lifecycle, provisional_need_id)
		VALUES ($1,$2,$3,'Provisional MCP','admin','https://mcp.example','oauth','https://provider.example/auth','https://provider.example/token','','read','{}','[]','','','','','','provisional',$4)`,
		provisionalMCP, user.ID, "provisional-mcp-"+suffix, needID); err != nil {
		t.Fatalf("seed provisional MCP: %v", err)
	}
	database.Close()
	if err := goose.DownToContext(t.Context(), migrationDB, "migrations", 1); err != nil {
		t.Fatalf("migration 002 down: %v", err)
	}
	database = New(t.Context(), url)
	for table, id := range map[string]uuid.UUID{"connections": provisionalConnection, "agent_mcp_servers": provisionalMCP} {
		var exists bool
		if err := database.Pool().QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=$1)`, id).Scan(&exists); err != nil || exists {
			t.Fatalf("%s provisional exists=%v err=%v after down", table, exists, err)
		}
	}
	var lifecycleColumns int
	if err := database.Pool().QueryRow(t.Context(), `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema='public' AND column_name='lifecycle' AND table_name IN ('connections','agent_mcp_servers')`).Scan(&lifecycleColumns); err != nil || lifecycleColumns != 0 {
		t.Fatalf("lifecycle columns after down = %d err=%v", lifecycleColumns, err)
	}
	database.Close()
	if err := goose.UpToContext(t.Context(), migrationDB, "migrations", 2); err != nil {
		t.Fatalf("restore migration 002: %v", err)
	}
}
