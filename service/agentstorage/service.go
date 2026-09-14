// Package agentstorage owns authorization and canonical resolution for paths
// supplied through user, run, and MCP surfaces. Framework-trusted storage
// operations use the low-level storage package directly.
package agentstorage

import (
	"context"
	"errors"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type Operation string

const (
	OperationRead      Operation = "read"
	OperationList      Operation = "list"
	OperationWrite     Operation = "write"
	OperationOverwrite Operation = "overwrite"
	OperationDelete    Operation = "delete"
)

type Caller struct {
	Principal      authz.Principal
	Access         agentsdk.Access
	UserID         uuid.UUID
	ConversationID uuid.UUID
	RunID          uuid.UUID
	ParentRunID    uuid.UUID
	ScopeBound     bool
}

type ResolvedPath struct {
	Relative string
	S3Key    string
}

type ListRoot struct {
	ResolvedPath
	DirectoryPath string
	Description   string
}

type Service struct {
	db *db.DB
}

func New(database *db.DB) *Service {
	if database == nil {
		panic("agentstorage: db is required")
	}
	return &Service{db: database}
}

func (s *Service) Resolve(ctx context.Context, caller Caller, agentID uuid.UUID, path string, op Operation) (ResolvedPath, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, caller.Principal, authz.AgentFileResolve, agentID); err != nil {
		return ResolvedPath{}, err
	}
	return resolve(ctx, q, caller, agentID, path, op)
}

func (s *Service) ResolveForRun(ctx context.Context, agentID, runID uuid.UUID, path string, op Operation) (ResolvedPath, error) {
	q := dbq.New(s.db.Pool())
	admitted, err := execution.Resolve(ctx, q, agentID, runID)
	if err != nil {
		return ResolvedPath{}, err
	}
	return s.ResolveForRuntime(ctx, admitted.Runtime, path, op)
}

// ResolveForRuntime applies the broker's live access ceiling to the durable run
// identity. A grant downgrade cannot retain access through an older run snapshot.
func (s *Service) ResolveForRuntime(ctx context.Context, scope wire.RuntimeContext, path string, op Operation) (ResolvedPath, error) {
	agentID, err := uuid.Parse(scope.AgentID)
	if err != nil {
		return ResolvedPath{}, service.ErrInvalidInput
	}
	runID, err := uuid.Parse(scope.RunID)
	if err != nil {
		return ResolvedPath{}, service.ErrInvalidInput
	}
	q := dbq.New(s.db.Pool())
	admitted, err := execution.Resolve(ctx, q, agentID, runID)
	if err != nil {
		return ResolvedPath{}, err
	}
	action := authz.AgentFileResolve
	if admitted.Origin.Actor == "app" {
		action = authz.AppRuntime
	}
	if err := authz.Authorize(ctx, q, admitted.Principal, action, agentID); err != nil {
		return ResolvedPath{}, err
	}
	run := admitted.Run
	access := agentsdk.Access(scope.Caller.Access)
	if !validAccess(access) {
		return ResolvedPath{}, service.ErrForbidden
	}
	if !authz.AccessAtLeast(agentsdk.Access(admitted.Runtime.Caller.Access), access) {
		access = agentsdk.Access(admitted.Runtime.Caller.Access)
	}
	caller := Caller{Principal: admitted.Principal, Access: access, RunID: runID, ScopeBound: admitted.Runtime.Definition != nil}
	if run.CallerUserID.Valid {
		caller.UserID = uuid.UUID(run.CallerUserID.Bytes)
	}
	if run.CallerConversationID.Valid {
		caller.ConversationID = uuid.UUID(run.CallerConversationID.Bytes)
	}
	return resolve(ctx, q, caller, agentID, path, op)
}

func (s *Service) ListRoots(ctx context.Context, caller Caller, agentID uuid.UUID) ([]ListRoot, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, caller.Principal, authz.AgentFileResolve, agentID); err != nil {
		return nil, err
	}
	dirs, err := q.ListDirectoriesByAgent(ctx, dbUUID(agentID))
	if err != nil {
		return nil, err
	}
	roots := make([]ListRoot, 0, len(dirs))
	for _, dir := range dirs {
		if dir.Path == "__incoming" {
			continue
		}
		path, err := resolveDirectoryPath(dir, caller, dir.Path, OperationList)
		if errors.Is(err, service.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		roots = append(roots, ListRoot{
			ResolvedPath:  ResolvedPath{Relative: path, S3Key: "agents/" + agentID.String() + "/" + path},
			DirectoryPath: dir.Path,
			Description:   dir.Description,
		})
	}
	return roots, nil
}

func (s *Service) FilterList(ctx context.Context, caller Caller, agentID uuid.UUID, paths []string) ([]ResolvedPath, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, caller.Principal, authz.AgentFileResolve, agentID); err != nil {
		return nil, err
	}
	dirs, err := q.ListDirectoriesByAgent(ctx, dbUUID(agentID))
	if err != nil {
		return nil, err
	}
	resolved := make([]ResolvedPath, 0, len(paths))
	for _, path := range paths {
		canonical, err := storage.CleanAgentPath(path)
		if err != nil {
			continue
		}
		dir, ok := longestDirectory(dirs, canonical)
		if !ok || dir.Path == "__incoming" {
			continue
		}
		path, err := resolveDirectoryPath(dir, caller, canonical, OperationList)
		if errors.Is(err, service.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if path != canonical {
			continue
		}
		resolved = append(resolved, ResolvedPath{Relative: path, S3Key: "agents/" + agentID.String() + "/" + path})
	}
	return resolved, nil
}

func resolve(ctx context.Context, q *dbq.Queries, caller Caller, agentID uuid.UUID, path string, op Operation) (ResolvedPath, error) {
	if !validOperation(op) {
		return ResolvedPath{}, service.Detail(service.ErrInvalidInput, "unsupported file operation %q", op)
	}
	canonical, err := storage.CleanAgentPath(path)
	if err != nil {
		return ResolvedPath{}, service.Detail(service.ErrInvalidInput, "invalid file path")
	}
	dir, err := q.GetDirectoryByPath(ctx, dbq.GetDirectoryByPathParams{AgentID: dbUUID(agentID), Path: canonical})
	if errors.Is(err, pgx.ErrNoRows) {
		return ResolvedPath{}, service.ErrNotFound
	}
	if err != nil {
		return ResolvedPath{}, err
	}
	resolved, err := resolveDirectoryPath(dir, caller, canonical, op)
	if err != nil {
		return ResolvedPath{}, err
	}
	return ResolvedPath{Relative: resolved, S3Key: "agents/" + agentID.String() + "/" + resolved}, nil
}

func resolveDirectoryPath(dir dbq.AgentDirectory, caller Caller, path string, op Operation) (string, error) {
	if !validAccess(caller.Access) {
		return "", service.ErrNotFound
	}
	required := dir.ReadAccess
	switch op {
	case OperationList:
		required = dir.ListAccess
	case OperationWrite, OperationOverwrite, OperationDelete:
		required = dir.WriteAccess
	}
	if !validAccess(agentsdk.Access(required)) {
		return "", service.ErrNotFound
	}
	if caller.Access == agentsdk.AccessAdmin && !caller.ScopeBound {
		return path, nil
	}
	if dir.Path == "__incoming" {
		return resolveIncomingPath(caller, path, op)
	}
	if !authz.AccessAtLeast(caller.Access, agentsdk.Access(required)) {
		return "", service.ErrNotFound
	}
	if dir.Scope == "" {
		return path, nil
	}
	if dir.Scope != "user" && dir.Scope != "conv" && dir.Scope != "run" {
		return "", service.ErrNotFound
	}
	expected := scopeSegment(dir.Scope, caller)
	if expected == "" {
		return "", service.ErrNotFound
	}
	if path == dir.Path {
		if op == OperationList {
			return dir.Path + "/" + expected, nil
		}
		if op == OperationWrite {
			return "", service.Detail(service.ErrInvalidInput, "write path must include a filename")
		}
		return "", service.ErrNotFound
	}
	rest := strings.TrimPrefix(path, dir.Path+"/")
	segment, _, _ := strings.Cut(rest, "/")
	if segment == expected {
		return path, nil
	}
	if isScopeSegment(segment) {
		return "", service.ErrNotFound
	}
	if op == OperationWrite || op == OperationList {
		return dir.Path + "/" + expected + "/" + rest, nil
	}
	return "", service.ErrNotFound
}

func resolveIncomingPath(caller Caller, path string, op Operation) (string, error) {
	if op != OperationRead || path == "__incoming" || !strings.HasPrefix(path, "__incoming/") {
		return "", service.ErrNotFound
	}
	rest := strings.TrimPrefix(path, "__incoming/")
	segment, _, hasFile := strings.Cut(rest, "/")
	if !hasFile {
		return "", service.ErrNotFound
	}
	allowed := []string{}
	if caller.UserID != uuid.Nil {
		allowed = append(allowed, "user-"+caller.UserID.String())
	}
	if caller.ConversationID != uuid.Nil {
		allowed = append(allowed, "conv-"+caller.ConversationID.String())
	}
	if caller.RunID != uuid.Nil {
		allowed = append(allowed, "run-"+caller.RunID.String())
	}
	for _, expected := range allowed {
		if segment == expected {
			return path, nil
		}
	}
	return "", service.ErrNotFound
}

func validOperation(op Operation) bool {
	switch op {
	case OperationRead, OperationList, OperationWrite, OperationOverwrite, OperationDelete:
		return true
	default:
		return false
	}
}

func validAccess(access agentsdk.Access) bool {
	return access == agentsdk.AccessPublic || access == agentsdk.AccessUser || access == agentsdk.AccessAdmin
}

func scopeSegment(scope string, caller Caller) string {
	switch scope {
	case "user":
		if caller.UserID != uuid.Nil {
			return "user-" + caller.UserID.String()
		}
	case "conv":
		if caller.ConversationID != uuid.Nil {
			return "conv-" + caller.ConversationID.String()
		}
	case "run":
		if caller.RunID != uuid.Nil {
			return "run-" + caller.RunID.String()
		}
	}
	return ""
}

func isScopeSegment(segment string) bool {
	return strings.HasPrefix(segment, "user-") || strings.HasPrefix(segment, "conv-") || strings.HasPrefix(segment, "run-")
}

func longestDirectory(dirs []dbq.AgentDirectory, path string) (dbq.AgentDirectory, bool) {
	var best dbq.AgentDirectory
	found := false
	for _, dir := range dirs {
		if path != dir.Path && !strings.HasPrefix(path, dir.Path+"/") {
			continue
		}
		if !found || len(dir.Path) > len(best.Path) {
			best = dir
			found = true
		}
	}
	return best, found
}

func dbUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}
