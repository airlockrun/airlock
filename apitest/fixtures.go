package apitest

import (
	"context"
	"testing"
	"time"

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
	Name              string
	Slug              string
	OwnerID           uuid.UUID
	AllowPublicMCP    bool
	AllowPublicChat   bool
	AllowPublicRoutes bool
	// Stopped parks the agent at status='stopped' (image_ref still set) so
	// EnsureRunning refuses it — used to exercise the not-runnable paths.
	Stopped bool
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
		Name:             opts.Name,
		Slug:             opts.Slug,
		OwnerPrincipalID: pgtype.UUID{Bytes: opts.OwnerID, Valid: true},
		Config:           []byte("{}"),
	})
	if err != nil {
		t.Fatalf("apitest: CreateAgent %q: %v", opts.Name, err)
	}
	agentID := uuid.UUID(row.ID.Bytes)

	if err := q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{
		AgentID:   row.ID,
		GranteeID: pgtype.UUID{Bytes: opts.OwnerID, Valid: true},
		Role:      "admin",
	}); err != nil {
		t.Fatalf("apitest: UpsertAgentGrant (owner): %v", err)
	}

	encryptedPW, err := h.Secrets.Put(ctx, "agent/"+agentID.String()+"/db_password", "apitest-stub-password")
	if err != nil {
		t.Fatalf("apitest: encrypt db_password: %v", err)
	}

	status := "active"
	if opts.Stopped {
		status = "stopped"
	}
	if _, err := h.DB.Pool().Exec(ctx,
		`UPDATE agents
		    SET status=$2,
		        image_ref='apitest:stub',
		        db_password=$3,
		        allow_public_mcp=$4,
		        allow_public_mcp_prompt=$5,
		        allow_public_routes=$6
		  WHERE id=$1`,
		row.ID, status, encryptedPW, opts.AllowPublicMCP, opts.AllowPublicChat, opts.AllowPublicRoutes,
	); err != nil {
		t.Fatalf("apitest: stamp agent status: %v", err)
	}

	return agentID
}

// AddAgentMember grants role on agentID to userID. role is "admin"
// or "user".
func AddAgentMember(t *testing.T, h *Harness, agentID, userID uuid.UUID, role string) {
	t.Helper()
	q := dbq.New(h.DB.Pool())
	err := q.UpsertAgentGrant(context.Background(), dbq.UpsertAgentGrantParams{
		AgentID:   pgtype.UUID{Bytes: agentID, Valid: true},
		GranteeID: pgtype.UUID{Bytes: userID, Valid: true},
		Role:      role,
	})
	if err != nil {
		t.Fatalf("apitest: UpsertAgentGrant: %v", err)
	}
}

// AddSibling declares a caller-to-target A2A edge authorized by a grant the
// target already has for authorizingGranteeID.
func AddSibling(t *testing.T, h *Harness, callerID, targetID, authorizingGranteeID uuid.UUID, maxAccess string) {
	t.Helper()
	err := dbq.New(h.DB.Pool()).AddSibling(context.Background(), dbq.AddSiblingParams{
		ParentAgentID:        pgtype.UUID{Bytes: callerID, Valid: true},
		SiblingAgentID:       pgtype.UUID{Bytes: targetID, Valid: true},
		MaxAccess:            maxAccess,
		AuthorizingGranteeID: pgtype.UUID{Bytes: authorizingGranteeID, Valid: true},
	})
	if err != nil {
		t.Fatalf("apitest: AddSibling: %v", err)
	}
}

// IssueUserToken creates an active first-party session and mints its access
// JWT with the harness JWT secret.
func IssueUserToken(t *testing.T, h *Harness, userID uuid.UUID, email, role string) string {
	t.Helper()
	q := dbq.New(h.DB.Pool())
	ctx := context.Background()
	user, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: userID, Valid: true})
	if err != nil {
		t.Fatalf("apitest: GetUserByID: %v", err)
	}
	now := time.Now()
	session, err := q.CreateUserSession(ctx, dbq.CreateUserSessionParams{
		UserID:           user.ID,
		Kind:             "web",
		ClientName:       "apitest",
		DeviceName:       "apitest",
		RefreshTokenHash: []byte(uuid.NewString()),
		AuthenticatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
		ExpiresAt:        pgtype.Timestamptz{Time: now.Add(auth.RefreshTokenDuration), Valid: true},
	})
	if err != nil {
		t.Fatalf("apitest: CreateUserSession: %v", err)
	}
	tok, err := auth.IssueUserAccessToken(h.JWTSecret, userID, email, user.DisplayName, role, user.MustChangePassword, uuid.UUID(session.ID.Bytes), user.AuthEpoch, now)
	if err != nil {
		t.Fatalf("apitest: IssueUserToken: %v", err)
	}
	return tok
}

// IssueAgentToken mints an agent JWT at the row's live token version. Used by
// tests driving /api/agent/* endpoints directly.
func IssueAgentToken(t *testing.T, h *Harness, agentID uuid.UUID) string {
	t.Helper()
	state, err := dbq.New(h.DB.Pool()).GetAgentTokenAuth(context.Background(), pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		t.Fatalf("apitest: GetAgentTokenAuth: %v", err)
	}
	tok, err := auth.IssueAgentToken(h.JWTSecret, agentID, state.AgentTokenVersion)
	if err != nil {
		t.Fatalf("apitest: IssueAgentToken: %v", err)
	}
	return tok
}
