package agentstorage

import (
	"errors"
	"testing"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
)

func TestResolveDirectoryPath(t *testing.T) {
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	otherUserID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	conversationID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	runID := uuid.MustParse("44444444-4444-4444-4444-444444444444")

	tests := []struct {
		name    string
		dir     dbq.AgentDirectory
		caller  Caller
		path    string
		op      Operation
		want    string
		wantErr error
	}{
		{name: "unscoped public read", dir: directory("docs", "public", "user", "public", ""), caller: Caller{Access: agentsdk.AccessPublic}, path: "docs/a.txt", op: OperationRead, want: "docs/a.txt"},
		{name: "access denied", dir: directory("docs", "user", "user", "user", ""), caller: Caller{Access: agentsdk.AccessPublic}, path: "docs/a.txt", op: OperationRead, wantErr: service.ErrNotFound},
		{name: "user read exact", dir: directory("private", "user", "user", "user", "user"), caller: Caller{Access: agentsdk.AccessUser, UserID: userID}, path: "private/user-" + userID.String() + "/a.txt", op: OperationRead, want: "private/user-" + userID.String() + "/a.txt"},
		{name: "cross user denied", dir: directory("private", "user", "user", "user", "user"), caller: Caller{Access: agentsdk.AccessUser, UserID: userID}, path: "private/user-" + otherUserID.String() + "/a.txt", op: OperationRead, wantErr: service.ErrNotFound},
		{name: "bare user write inserts scope", dir: directory("private", "user", "user", "user", "user"), caller: Caller{Access: agentsdk.AccessUser, UserID: userID}, path: "private/a.txt", op: OperationWrite, want: "private/user-" + userID.String() + "/a.txt"},
		{name: "bare list inserts scope", dir: directory("threads", "user", "user", "user", "conv"), caller: Caller{Access: agentsdk.AccessUser, ConversationID: conversationID}, path: "threads", op: OperationList, want: "threads/conv-" + conversationID.String()},
		{name: "conversation absent", dir: directory("threads", "public", "public", "public", "conv"), caller: Caller{Access: agentsdk.AccessPublic}, path: "threads/a.txt", op: OperationRead, wantErr: service.ErrNotFound},
		{name: "run overwrite exact", dir: directory("jobs", "user", "user", "user", "run"), caller: Caller{Access: agentsdk.AccessUser, RunID: runID}, path: "jobs/run-" + runID.String() + "/a.txt", op: OperationOverwrite, want: "jobs/run-" + runID.String() + "/a.txt"},
		{name: "run delete guessed denied", dir: directory("jobs", "user", "user", "user", "run"), caller: Caller{Access: agentsdk.AccessUser, RunID: runID}, path: "jobs/a.txt", op: OperationDelete, wantErr: service.ErrNotFound},
		{name: "admin bypasses scope", dir: directory("jobs", "admin", "admin", "admin", "run"), caller: Caller{Access: agentsdk.AccessAdmin}, path: "jobs/run-" + runID.String() + "/a.txt", op: OperationRead, want: "jobs/run-" + runID.String() + "/a.txt"},
		{name: "incoming parent run exact", dir: directory("__incoming", "admin", "admin", "admin", ""), caller: Caller{Access: agentsdk.AccessPublic, ParentRunID: runID}, path: "__incoming/run-" + runID.String() + "/a.txt", op: OperationRead, want: "__incoming/run-" + runID.String() + "/a.txt"},
		{name: "incoming public run is not current run", dir: directory("__incoming", "admin", "admin", "admin", ""), caller: Caller{Access: agentsdk.AccessPublic, RunID: runID}, path: "__incoming/run-" + runID.String() + "/a.txt", op: OperationRead, wantErr: service.ErrNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDirectoryPath(tt.dir, tt.caller, tt.path, tt.op)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("path = %q, want %q", got, tt.want)
			}
		})
	}
}

func directory(path, read, write, list, scope string) dbq.AgentDirectory {
	return dbq.AgentDirectory{Path: path, ReadAccess: read, WriteAccess: write, ListAccess: list, Scope: scope}
}
