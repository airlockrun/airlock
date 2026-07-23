package agentapi

import (
	"context"
	"sync"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
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
		{name: "undeclared edge is forbidden", driverRole: "admin", ownerRole: "admin", edge: "", wantErr: true},
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

func TestComputeA2ACallerAccess_RemovedEdgeDenied(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	callerID, callerOwner := testAgentAndUser(t)
	targetID, _ := testAgentAndUser(t)
	driver := makeUser(t)
	grantAccess(t, targetID, driver, "admin")
	grantAccess(t, targetID, callerOwner, "admin")
	addSiblingEdge(t, callerID, targetID, callerOwner, "admin")
	target, err := q.GetAgentByID(ctx, toPgUUID(targetID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	principal := MCPPrincipal{Kind: MCPPrincipalAgent, UserID: driver, CallerAgentID: callerID}
	if _, err := computeA2ACallerAccess(ctx, q, target, principal); err != nil {
		t.Fatalf("declared edge denied: %v", err)
	}
	if err := q.RemoveSibling(ctx, dbq.RemoveSiblingParams{
		ParentAgentID: toPgUUID(callerID), SiblingAgentID: toPgUUID(targetID),
	}); err != nil {
		t.Fatalf("RemoveSibling: %v", err)
	}
	if _, err := computeA2ACallerAccess(ctx, q, target, principal); err == nil {
		t.Fatal("removed sibling edge retained A2A access")
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

func createBoundMCPConversation(t *testing.T, agentID uuid.UUID, principal MCPPrincipal) dbq.AgentConversation {
	t.Helper()
	metadata, err := continuationMetadata(principal)
	if err != nil {
		t.Fatalf("continuationMetadata: %v", err)
	}
	conv, err := dbq.New(testDB.Pool()).CreateMCPA2AConversation(context.Background(), dbq.CreateMCPA2AConversationParams{
		AgentID: toPgUUID(agentID), UserID: toPgUUID(principal.UserID), Title: "bound", Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("CreateMCPA2AConversation: %v", err)
	}
	return conv
}

func createTestRun(t *testing.T, agentID uuid.UUID, parentRunID pgtype.UUID, triggerType, triggerRef string) dbq.Run {
	t.Helper()
	run, err := dbq.New(testDB.Pool()).CreateRun(context.Background(), dbq.CreateRunParams{
		AgentID: toPgUUID(agentID), ParentRunID: parentRunID, InputPayload: []byte(`{}`),
		SourceRef: "", TriggerType: triggerType, TriggerRef: triggerRef, CallerAccess: "public",
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	return run
}

func TestMCPContinuationPrincipalAndTaskIsolation(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	targetID, _ := testAgentAndUser(t)
	callerID, _ := testAgentAndUser(t)
	userID := makeUser(t)
	parentConv, err := q.CreateWebConversation(ctx, dbq.CreateWebConversationParams{
		AgentID: toPgUUID(callerID), UserID: toPgUUID(userID), Title: "parent",
	})
	if err != nil {
		t.Fatalf("CreateWebConversation: %v", err)
	}
	parent := createTestRun(t, callerID, pgtype.UUID{}, "prompt", pgUUID(parentConv.ID).String())
	principal := MCPPrincipal{
		Kind: MCPPrincipalAgent, UserID: userID, CallerAgentID: callerID, ParentRunID: pgUUID(parent.ID),
	}
	conv := createBoundMCPConversation(t, targetID, principal)
	convID := pgUUID(conv.ID).String()
	child := createTestRun(t, targetID, parent.ID, "a2a", convID)
	if _, err := testDB.Pool().Exec(ctx, `UPDATE runs SET status = 'suspended' WHERE id = $1`, child.ID); err != nil {
		t.Fatalf("suspend child: %v", err)
	}

	if _, err := getBoundMCPConversation(ctx, q, targetID, principal, convID); err != nil {
		t.Fatalf("bound conversation denied: %v", err)
	}
	if _, _, err := getBoundMCPTask(ctx, q, targetID, principal, pgUUID(child.ID).String(), convID); err != nil {
		t.Fatalf("bound suspended task denied: %v", err)
	}
	resumeParent, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID: toPgUUID(callerID), InputPayload: []byte(`{"resumeRunId":"` + pgUUID(parent.ID).String() + `"}`),
		SourceRef: "", TriggerType: "prompt", TriggerRef: pgUUID(parentConv.ID).String(), CallerAccess: "public",
	})
	if err != nil {
		t.Fatalf("CreateRun resume parent: %v", err)
	}
	resumePrincipal := principal
	resumePrincipal.ParentRunID = pgUUID(resumeParent.ID)
	if _, _, err := getBoundMCPTask(ctx, q, targetID, resumePrincipal, pgUUID(child.ID).String(), ""); err != nil {
		t.Fatalf("linked running resume parent denied: %v", err)
	}

	tests := []struct {
		name      string
		principal MCPPrincipal
		contextID string
	}{
		{name: "other user", principal: MCPPrincipal{Kind: MCPPrincipalAgent, UserID: makeUser(t), CallerAgentID: callerID, ParentRunID: pgUUID(parent.ID)}, contextID: convID},
		{name: "other parent run", principal: MCPPrincipal{Kind: MCPPrincipalAgent, UserID: userID, CallerAgentID: callerID, ParentRunID: uuid.New()}, contextID: convID},
		{name: "other caller agent", principal: MCPPrincipal{Kind: MCPPrincipalAgent, UserID: userID, CallerAgentID: uuid.New(), ParentRunID: pgUUID(parent.ID)}, contextID: convID},
		{name: "anonymous", principal: MCPPrincipal{Kind: MCPPrincipalAnon}, contextID: convID},
		{name: "mismatched context", principal: principal, contextID: uuid.NewString()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := getBoundMCPTask(ctx, q, targetID, tc.principal, pgUUID(child.ID).String(), tc.contextID); err == nil {
				t.Fatal("cross-principal task resume allowed")
			}
		})
	}
	unchanged, err := q.GetRunByID(ctx, child.ID)
	if err != nil {
		t.Fatalf("GetRunByID after denied resumes: %v", err)
	}
	if unchanged.Status != "suspended" {
		t.Fatalf("denied context/task pair changed status to %q", unchanged.Status)
	}

	if _, err := testDB.Pool().Exec(ctx, `UPDATE runs SET status = 'success' WHERE id = $1`, child.ID); err != nil {
		t.Fatalf("complete child: %v", err)
	}
	if _, _, err := getBoundMCPTask(ctx, q, targetID, principal, pgUUID(child.ID).String(), convID); err == nil {
		t.Fatal("terminal task resume allowed")
	}
}

func TestMCPTaskResumeClaimIsSingleUse(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	targetID, _ := testAgentAndUser(t)
	userID := makeUser(t)
	principal := MCPPrincipal{Kind: MCPPrincipalUser, UserID: userID}
	conv := createBoundMCPConversation(t, targetID, principal)
	convID := pgUUID(conv.ID).String()
	task := createTestRun(t, targetID, pgtype.UUID{}, "a2a", convID)
	if _, err := testDB.Pool().Exec(ctx, `UPDATE runs SET status = 'suspended' WHERE id = $1`, task.ID); err != nil {
		t.Fatalf("suspend task: %v", err)
	}

	const contenders = 16
	start := make(chan struct{})
	results := make(chan error, contenders)
	var wg sync.WaitGroup
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			run, _, err := getBoundMCPTask(ctx, q, targetID, principal, pgUUID(task.ID).String(), convID)
			if err == nil {
				err = claimMCPTaskResume(ctx, q, run)
			}
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent claims = %d, want 1", successes)
	}
	run, err := q.GetRunByID(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetRunByID: %v", err)
	}
	if run.Status != "success" {
		t.Fatalf("claimed task status = %q, want success", run.Status)
	}
}

func TestMCPTaskResumeRollbackRequiresNoSuccessor(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	targetID, _ := testAgentAndUser(t)
	userID := makeUser(t)
	principal := MCPPrincipal{Kind: MCPPrincipalUser, UserID: userID}
	conv := createBoundMCPConversation(t, targetID, principal)
	convID := pgUUID(conv.ID).String()
	task := createTestRun(t, targetID, pgtype.UUID{}, "a2a", convID)
	if _, err := testDB.Pool().Exec(ctx, `UPDATE runs SET status = 'suspended' WHERE id = $1`, task.ID); err != nil {
		t.Fatalf("suspend task: %v", err)
	}
	run, _, err := getBoundMCPTask(ctx, q, targetID, principal, pgUUID(task.ID).String(), convID)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	if err := claimMCPTaskResume(ctx, q, run); err != nil {
		t.Fatalf("claim task: %v", err)
	}
	params := dbq.RollbackMCPTaskResumeParams{ID: task.ID, AgentID: toPgUUID(targetID), TriggerRef: convID}
	rolledBack, err := q.RollbackMCPTaskResume(ctx, params)
	if err != nil || rolledBack != 1 {
		t.Fatalf("rollback without successor = (%d, %v), want (1, nil)", rolledBack, err)
	}

	run, _, err = getBoundMCPTask(ctx, q, targetID, principal, pgUUID(task.ID).String(), convID)
	if err != nil {
		t.Fatalf("get rolled-back task: %v", err)
	}
	if err := claimMCPTaskResume(ctx, q, run); err != nil {
		t.Fatalf("reclaim task: %v", err)
	}
	resumePayload := []byte(`{"resumeRunId":"` + pgUUID(task.ID).String() + `"}`)
	if _, err := q.CreateRun(ctx, dbq.CreateRunParams{
		AgentID: toPgUUID(targetID), InputPayload: resumePayload, SourceRef: "",
		TriggerType: "a2a", TriggerRef: convID, CallerAccess: "public",
	}); err != nil {
		t.Fatalf("CreateRun successor: %v", err)
	}
	rolledBack, err = q.RollbackMCPTaskResume(ctx, params)
	if err != nil || rolledBack != 0 {
		t.Fatalf("rollback with successor = (%d, %v), want (0, nil)", rolledBack, err)
	}
	claimed, err := q.GetRunByID(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetRunByID claimed task: %v", err)
	}
	if claimed.Status != "success" {
		t.Fatalf("task with successor status = %q, want success", claimed.Status)
	}
}
