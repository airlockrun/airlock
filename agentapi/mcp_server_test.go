package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func TestNormalizeMCPRequestID(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "string", raw: `"request-1"`, want: `"request-1"`},
		{name: "number", raw: `42`, want: `42`},
		{name: "number whitespace", raw: ` 42 `, want: `42`},
		{name: "null", raw: `null`, wantErr: true},
		{name: "boolean", raw: `true`, wantErr: true},
		{name: "object", raw: `{}`, wantErr: true},
		{name: "missing", raw: ``, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeMCPRequestID(json.RawMessage(tc.raw))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeMCPRequestID(%q) succeeded", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeMCPRequestID(%q): %v", tc.raw, err)
			}
			if string(got) != tc.want {
				t.Fatalf("normalizeMCPRequestID(%q) = %s, want %s", tc.raw, got, tc.want)
			}
		})
	}
}

func TestMCPCancelledNotificationConsumesMatchingRequest(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	targetID, userID := testAgentAndUser(t)
	target, err := q.GetAgentByID(ctx, toPgUUID(targetID))
	if err != nil {
		t.Fatalf("GetAgentByID: %v", err)
	}
	run := createTestRun(t, targetID, pgtype.UUID{}, "a2a", "")
	principal := MCPPrincipal{Kind: MCPPrincipalUser, UserID: userID}
	principalIdentity, ok := continuationPrincipalKey(principal)
	if !ok {
		t.Fatal("user principal has no identity")
	}
	requestID := []byte(`"call-1"`)
	registerMCPRequest(t, q, target.ID, principalIdentity, requestID, run.ID, 60)

	dispatcher := trigger.NewDispatcher(&config.Config{}, testDB, nil, testEncryptor(), zap.NewNop())
	server := &MCPServer{dispatcher: dispatcher, logger: zap.NewNop()}
	server.handleCancelled(ctx, q, target, principal, cancelledMessage(requestID))

	_, err = q.GetMCPActiveRequest(ctx, dbq.GetMCPActiveRequestParams{
		TargetAgentID:     target.ID,
		PrincipalIdentity: principalIdentity,
		RequestID:         requestID,
		RunID:             run.ID,
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("active request remains after cancellation: %v", err)
	}
}

func TestMCPActiveRequestWatcherObservesRemoteCancellation(t *testing.T) {
	skipIfNoDB(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	q := dbq.New(testDB.Pool())
	targetID, userID := testAgentAndUser(t)
	run := createTestRun(t, targetID, pgtype.UUID{}, "a2a", "")
	principalIdentity, _ := continuationPrincipalKey(MCPPrincipal{Kind: MCPPrincipalUser, UserID: userID})
	requestID := []byte(`"remote-call"`)
	registerMCPRequest(t, q, toPgUUID(targetID), principalIdentity, requestID, run.ID, 60)

	server := &MCPServer{logger: zap.NewNop()}
	cancelled := make(chan struct{})
	watchDone := make(chan struct{})
	var once sync.Once
	go server.watchMCPActiveRequest(ctx, q, toPgUUID(targetID), principalIdentity, requestID, pgUUID(run.ID), func() {
		once.Do(func() { close(cancelled) })
	}, watchDone)

	if _, err := q.ConsumeMCPActiveRequest(ctx, dbq.ConsumeMCPActiveRequestParams{
		TargetAgentID:     toPgUUID(targetID),
		PrincipalIdentity: principalIdentity,
		RequestID:         requestID,
	}); err != nil {
		t.Fatalf("ConsumeMCPActiveRequest: %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("request owner did not observe remote cancellation")
	}
	select {
	case <-watchDone:
	case <-time.After(2 * time.Second):
		t.Fatal("active request watcher did not stop")
	}
}

func TestMCPCancelledNotificationIsPrincipalAndTargetBound(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	targetID, userID := testAgentAndUser(t)
	otherTargetID, _ := testAgentAndUser(t)
	target, err := q.GetAgentByID(ctx, toPgUUID(targetID))
	if err != nil {
		t.Fatalf("GetAgentByID target: %v", err)
	}
	otherTarget, err := q.GetAgentByID(ctx, toPgUUID(otherTargetID))
	if err != nil {
		t.Fatalf("GetAgentByID other target: %v", err)
	}
	run := createTestRun(t, targetID, pgtype.UUID{}, "a2a", "")
	owner := MCPPrincipal{Kind: MCPPrincipalOAuthClient, UserID: userID, ClientID: "client-a"}
	ownerIdentity, ok := continuationPrincipalKey(owner)
	if !ok {
		t.Fatal("OAuth principal has no identity")
	}
	requestID := []byte(`7`)
	registerMCPRequest(t, q, target.ID, ownerIdentity, requestID, run.ID, 60)

	dispatcher := trigger.NewDispatcher(&config.Config{}, testDB, nil, testEncryptor(), zap.NewNop())
	server := &MCPServer{dispatcher: dispatcher, logger: zap.NewNop()}
	tests := []struct {
		name      string
		target    dbq.Agent
		principal MCPPrincipal
	}{
		{name: "other user", target: target, principal: MCPPrincipal{Kind: MCPPrincipalOAuthClient, UserID: uuid.New(), ClientID: "client-a"}},
		{name: "other OAuth client", target: target, principal: MCPPrincipal{Kind: MCPPrincipalOAuthClient, UserID: userID, ClientID: "client-b"}},
		{name: "agent principal", target: target, principal: MCPPrincipal{Kind: MCPPrincipalAgent, UserID: userID, CallerAgentID: uuid.New(), ParentRunID: uuid.New()}},
		{name: "other target", target: otherTarget, principal: owner},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server.handleCancelled(ctx, q, tc.target, tc.principal, cancelledMessage(requestID))
			if _, err := q.GetMCPActiveRequest(ctx, dbq.GetMCPActiveRequestParams{
				TargetAgentID:     target.ID,
				PrincipalIdentity: ownerIdentity,
				RequestID:         requestID,
				RunID:             run.ID,
			}); err != nil {
				t.Fatalf("owner mapping was consumed: %v", err)
			}
		})
	}
}

func TestCleanupExpiredMCPActiveRequests(t *testing.T) {
	skipIfNoDB(t)
	q := dbq.New(testDB.Pool())
	targetID, userID := testAgentAndUser(t)
	principalIdentity, _ := continuationPrincipalKey(MCPPrincipal{Kind: MCPPrincipalUser, UserID: userID})
	reserveMCPRequest(t, q, toPgUUID(targetID), principalIdentity, []byte(`1`), -1)

	deleted, err := q.CleanupExpiredMCPActiveRequests(context.Background())
	if err != nil {
		t.Fatalf("CleanupExpiredMCPActiveRequests: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
}

func TestMCPActiveRequestCancellationRacesActivation(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	targetID, userID := testAgentAndUser(t)
	run := createTestRun(t, targetID, pgtype.UUID{}, "a2a", "")
	principalIdentity, _ := continuationPrincipalKey(MCPPrincipal{Kind: MCPPrincipalUser, UserID: userID})

	for i := range 32 {
		requestID := []byte(fmt.Sprintf(`"activation-race-%d"`, i))
		reserveMCPRequest(t, q, toPgUUID(targetID), principalIdentity, requestID, 60)
		start := make(chan struct{})
		var wg sync.WaitGroup
		var activated int64
		var activateErr error
		var consumed pgtype.UUID
		var consumeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			activated, activateErr = q.ActivateMCPActiveRequest(ctx, dbq.ActivateMCPActiveRequestParams{
				TargetAgentID: toPgUUID(targetID), PrincipalIdentity: principalIdentity,
				RequestID: requestID, RunID: run.ID,
			})
		}()
		go func() {
			defer wg.Done()
			<-start
			consumed, consumeErr = q.ConsumeMCPActiveRequest(ctx, dbq.ConsumeMCPActiveRequestParams{
				TargetAgentID: toPgUUID(targetID), PrincipalIdentity: principalIdentity, RequestID: requestID,
			})
		}()
		close(start)
		wg.Wait()
		if activateErr != nil || consumeErr != nil {
			t.Fatalf("iteration %d: activate err = %v, consume err = %v", i, activateErr, consumeErr)
		}
		switch activated {
		case 0:
			if consumed.Valid {
				t.Fatalf("iteration %d: cancellation won but returned run %s", i, pgUUID(consumed))
			}
		case 1:
			if !consumed.Valid || consumed != run.ID {
				t.Fatalf("iteration %d: activation won but cancellation returned %+v", i, consumed)
			}
		default:
			t.Fatalf("iteration %d: activated rows = %d", i, activated)
		}
	}
}

func registerMCPRequest(t *testing.T, q *dbq.Queries, targetID pgtype.UUID, principalIdentity string, requestID []byte, runID pgtype.UUID, ttlSeconds int32) {
	t.Helper()
	reserveMCPRequest(t, q, targetID, principalIdentity, requestID, ttlSeconds)
	rows, err := q.ActivateMCPActiveRequest(context.Background(), dbq.ActivateMCPActiveRequestParams{
		TargetAgentID:     targetID,
		PrincipalIdentity: principalIdentity,
		RequestID:         requestID,
		RunID:             runID,
	})
	if err != nil {
		t.Fatalf("ActivateMCPActiveRequest: %v", err)
	}
	if rows != 1 {
		t.Fatalf("ActivateMCPActiveRequest rows = %d, want 1", rows)
	}
}

func reserveMCPRequest(t *testing.T, q *dbq.Queries, targetID pgtype.UUID, principalIdentity string, requestID []byte, ttlSeconds int32) {
	t.Helper()
	rows, err := q.ReserveMCPActiveRequest(context.Background(), dbq.ReserveMCPActiveRequestParams{
		TargetAgentID: targetID, PrincipalIdentity: principalIdentity,
		RequestID: requestID, TtlSeconds: ttlSeconds,
	})
	if err != nil {
		t.Fatalf("ReserveMCPActiveRequest: %v", err)
	}
	if rows != 1 {
		t.Fatalf("ReserveMCPActiveRequest rows = %d, want 1", rows)
	}
}

func cancelledMessage(requestID []byte) jsonrpcMessage {
	params, _ := json.Marshal(map[string]json.RawMessage{"requestId": requestID})
	return jsonrpcMessage{JSONRPC: "2.0", Method: "notifications/cancelled", Params: params}
}
