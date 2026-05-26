package apitest

import (
	"context"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AgentOpts configures a test agent. Zero values produce a
// minimum-viable row: status='active', image_ref='apitest:stub' so
// dispatcher.EnsureRunning skips the build path; db_password seeded
// with an encrypted dummy so the dispatcher's decrypt step succeeds.
type AgentOpts struct {
	Name            string
	Slug            string
	OwnerID         uuid.UUID
	AllowPublicMCP  bool
	AllowNonMember  bool
	AllowPublicChat bool
}

// CreateUser inserts a user with a unique email derived from name +
// random suffix. Returns the user's UUID; pair with IssueUserToken to
// drive authenticated requests.
func CreateUser(t *testing.T, h *Harness, name, role string) uuid.UUID {
	t.Helper()
	q := dbq.New(h.DB.Pool())
	suffix := uuid.New().String()[:8]
	row, err := q.CreateUser(context.Background(), dbq.CreateUserParams{
		Email:       name + "-" + suffix + "@apitest.local",
		DisplayName: name,
		TenantRole:  role,
	})
	if err != nil {
		t.Fatalf("apitest: CreateUser %q: %v", name, err)
	}
	return uuid.UUID(row.ID.Bytes)
}

// CreateAgent inserts an agent row past the build pipeline:
//   - status='active'
//   - image_ref='apitest:stub'
//   - db_password encrypted via Harness.Secrets (so EnsureRunning's
//     decrypt step succeeds).
//   - owner added as agent admin member.
func CreateAgent(t *testing.T, h *Harness, opts AgentOpts) uuid.UUID {
	t.Helper()
	if opts.OwnerID == uuid.Nil {
		t.Fatalf("apitest: CreateAgent: OwnerID is required")
	}
	suffix := uuid.New().String()[:8]
	if opts.Name == "" {
		opts.Name = "agent-" + suffix
	}
	if opts.Slug == "" {
		opts.Slug = "agent-" + suffix
	}

	ctx := context.Background()
	q := dbq.New(h.DB.Pool())
	row, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name:   opts.Name,
		Slug:   opts.Slug,
		UserID: pgtype.UUID{Bytes: opts.OwnerID, Valid: true},
		Config: []byte("{}"),
	})
	if err != nil {
		t.Fatalf("apitest: CreateAgent %q: %v", opts.Name, err)
	}
	agentID := uuid.UUID(row.ID.Bytes)

	if err := q.AddAgentMember(ctx, dbq.AddAgentMemberParams{
		AgentID: row.ID,
		UserID:  pgtype.UUID{Bytes: opts.OwnerID, Valid: true},
		Role:    "admin",
	}); err != nil {
		t.Fatalf("apitest: AddAgentMember (owner): %v", err)
	}

	encryptedPW, err := h.Secrets.Put(ctx, "agent/"+agentID.String()+"/db_password", "apitest-stub-password")
	if err != nil {
		t.Fatalf("apitest: encrypt db_password: %v", err)
	}

	if _, err := h.DB.Pool().Exec(ctx,
		`UPDATE agents
		    SET status='active',
		        image_ref='apitest:stub',
		        db_password=$2,
		        allow_non_member_mcp=$3,
		        allow_public_mcp=$4,
		        allow_public_mcp_prompt=$5
		  WHERE id=$1`,
		row.ID, encryptedPW, opts.AllowNonMember, opts.AllowPublicMCP, opts.AllowPublicChat,
	); err != nil {
		t.Fatalf("apitest: stamp agent active: %v", err)
	}

	return agentID
}

// AddAgentMember grants role on agentID to userID. role is "admin"
// or "user".
func AddAgentMember(t *testing.T, h *Harness, agentID, userID uuid.UUID, role string) {
	t.Helper()
	q := dbq.New(h.DB.Pool())
	err := q.AddAgentMember(context.Background(), dbq.AddAgentMemberParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
		UserID:  pgtype.UUID{Bytes: userID, Valid: true},
		Role:    role,
	})
	if err != nil {
		t.Fatalf("apitest: AddAgentMember: %v", err)
	}
}

// IssueUserToken mints a user-scoped JWT with the harness JWT secret.
// Pass the result as Authorization: Bearer or as the ?token= query
// parameter on the WS upgrade.
func IssueUserToken(t *testing.T, h *Harness, userID uuid.UUID, email, role string) string {
	t.Helper()
	tok, err := auth.IssueToken(h.JWTSecret, userID, email, role)
	if err != nil {
		t.Fatalf("apitest: IssueUserToken: %v", err)
	}
	return tok
}

// IssueAgentToken mints an agent JWT (100-year lifetime). Used by
// tests driving /api/agent/* endpoints directly.
func IssueAgentToken(t *testing.T, h *Harness, agentID uuid.UUID) string {
	t.Helper()
	tok, err := auth.IssueAgentToken(h.JWTSecret, agentID)
	if err != nil {
		t.Fatalf("apitest: IssueAgentToken: %v", err)
	}
	return tok
}
