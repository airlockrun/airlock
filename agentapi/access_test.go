package agentapi

import (
	"context"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

// makeUser inserts a standalone user and returns its id — used for a
// driving user distinct from any agent owner.
func makeUser(t *testing.T) uuid.UUID {
	t.Helper()
	q := dbq.New(testDB.Pool())
	suffix := uuid.New().String()[:8]
	u, err := q.CreateUser(context.Background(), dbq.CreateUserParams{
		Email:       "driver-" + suffix + "@example.com",
		DisplayName: "Driver",
		TenantRole:  "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return pgUUID(u.ID)
}

// grantAccess upserts (agent, grantee) → role in agent_grants.
func grantAccess(t *testing.T, agentID, granteeID uuid.UUID, role string) {
	t.Helper()
	q := dbq.New(testDB.Pool())
	if err := q.UpsertAgentGrant(context.Background(), dbq.UpsertAgentGrantParams{
		AgentID:   toPgUUID(agentID),
		GranteeID: toPgUUID(granteeID),
		Role:      role,
	}); err != nil {
		t.Fatalf("UpsertAgentGrant: %v", err)
	}
}

// addSiblingEdge inserts a parent→sibling address-book row at maxAccess
// anchored to an authorizing grant that must already exist (the FK).
func addSiblingEdge(t *testing.T, parent, sibling, authorizingGrantee uuid.UUID, maxAccess string) {
	t.Helper()
	_, err := testDB.Pool().Exec(context.Background(),
		`INSERT INTO agent_siblings (parent_agent_id, sibling_agent_id, max_access, authorizing_grantee_id)
		 VALUES ($1, $2, $3, $4)`,
		parent, sibling, maxAccess, authorizingGrantee)
	if err != nil {
		t.Fatalf("insert sibling edge: %v", err)
	}
}

// TestComputeA2ACallerAccess_AgentDelegation pins the A2A delegation ladder
// for a sibling-agent caller: admit only if BOTH the driving user and the
// acting agent's owner hold a grant on the target, then cap the effective
// access at min(driving-user, owner, per-edge max_access).
func TestComputeA2ACallerAccess_AgentDelegation(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())

	tests := []struct {
		name       string
		driverRole string // driving user's grant on target ("" = none)
		ownerRole  string // caller-owner's grant on target ("" = none)
		edge       string // per-edge max_access ("" = no edge row)
		want       agentsdk.Access
		wantErr    bool
	}{
		{name: "edge caps admin down to user", driverRole: "admin", ownerRole: "admin", edge: "user", want: agentsdk.AccessUser},
		{name: "edge admin leaves entitlement intact", driverRole: "admin", ownerRole: "admin", edge: "admin", want: agentsdk.AccessAdmin},
		{name: "owner floor below edge wins", driverRole: "admin", ownerRole: "user", edge: "admin", want: agentsdk.AccessUser},
		{name: "no edge means no extra cap", driverRole: "admin", ownerRole: "admin", edge: "", want: agentsdk.AccessAdmin},
		{name: "explicit public grant admitted, capped", driverRole: "public", ownerRole: "admin", edge: "user", want: agentsdk.AccessPublic},
		{name: "driver lacks grant -> forbidden", driverRole: "", ownerRole: "admin", edge: "", wantErr: true},
		{name: "owner lacks grant -> forbidden", driverRole: "admin", ownerRole: "", edge: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			callerID, callerOwner := testAgentAndUser(t)
			targetID, _ := testAgentAndUser(t)
			driver := makeUser(t) // distinct from the caller's owner

			if tc.driverRole != "" {
				grantAccess(t, targetID, driver, tc.driverRole)
			}
			if tc.ownerRole != "" {
				grantAccess(t, targetID, callerOwner, tc.ownerRole)
			}
			if tc.edge != "" {
				// The owner's grant anchors the edge (matches Add's choice).
				addSiblingEdge(t, callerID, targetID, callerOwner, tc.edge)
			}

			row, err := q.GetAgentByID(ctx, toPgUUID(targetID))
			if err != nil {
				t.Fatalf("GetAgentByID: %v", err)
			}

			got, err := computeA2ACallerAccess(ctx, q, row, MCPPrincipal{
				Kind:          MCPPrincipalAgent,
				UserID:        driver,
				CallerAgentID: callerID,
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got access %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("computeA2ACallerAccess: %v", err)
			}
			if got != tc.want {
				t.Errorf("access = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestComputeA2ACallerAccess_UserGrantGate pins the user/OAuth path: a
// registered caller is admitted only if a grant matches their grantee-set —
// a direct grant or the All-Users group (incl. an explicit 'public' grant).
// The bare floor (no matching grant) is denied.
func TestComputeA2ACallerAccess_UserGrantGate(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())

	t.Run("non-member denied", func(t *testing.T) {
		targetID, _ := testAgentAndUser(t)
		user := makeUser(t)
		row, _ := q.GetAgentByID(ctx, toPgUUID(targetID))
		if _, err := computeA2ACallerAccess(ctx, q, row, MCPPrincipal{Kind: MCPPrincipalUser, UserID: user}); err == nil {
			t.Fatalf("expected forbidden for non-member")
		}
	})

	t.Run("direct user grant admitted", func(t *testing.T) {
		targetID, _ := testAgentAndUser(t)
		user := makeUser(t)
		grantAccess(t, targetID, user, "user")
		row, _ := q.GetAgentByID(ctx, toPgUUID(targetID))
		got, err := computeA2ACallerAccess(ctx, q, row, MCPPrincipal{Kind: MCPPrincipalUser, UserID: user})
		if err != nil || got != agentsdk.AccessUser {
			t.Fatalf("got (%q, %v), want (user, nil)", got, err)
		}
	})

	t.Run("All-Users public grant admits at floor", func(t *testing.T) {
		targetID, _ := testAgentAndUser(t)
		user := makeUser(t)
		grantAccess(t, targetID, authz.GroupUser, "public")
		row, _ := q.GetAgentByID(ctx, toPgUUID(targetID))
		got, err := computeA2ACallerAccess(ctx, q, row, MCPPrincipal{Kind: MCPPrincipalUser, UserID: user})
		if err != nil || got != agentsdk.AccessPublic {
			t.Fatalf("got (%q, %v), want (public, nil)", got, err)
		}
	})
}
