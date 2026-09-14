// Package capabilities is the run-scoped authorization and dispatch boundary
// shared by direct tools and JavaScript capability callbacks.
package capabilities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/capability"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	agentstorage "github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type AppInvoker interface {
	InvokeRuntime(context.Context, uuid.UUID, wire.RuntimeInvokeRequest) (wire.RuntimeInvokeResponse, error)
}

type Platform interface {
	InvokePlatform(context.Context, wire.RuntimeContext, capability.Definition, json.RawMessage) (tool.Result, error)
	ValidateAppFiles(context.Context, wire.RuntimeContext, json.RawMessage, json.RawMessage) error
}

type Service struct {
	db       *db.DB
	app      AppInvoker
	platform Platform
	files    *agentstorage.Service
}

func New(database *db.DB, app AppInvoker, platform Platform) *Service {
	if database == nil || app == nil || platform == nil {
		panic("capabilities: database, app invoker and platform are required")
	}
	return &Service{db: database, app: app, platform: platform, files: agentstorage.New(database)}
}

// Scope is supplied by the host, never by script input or public HTTP headers.
// OwnerToken fences a hosted conversation run against lease loss.
type Scope struct {
	AgentID    uuid.UUID
	RunID      uuid.UUID
	OwnerToken uuid.UUID
}

func (s *Service) Catalog(ctx context.Context, scope Scope) ([]capability.Definition, error) {
	_, definitions, err := s.resolve(ctx, scope)
	return definitions, err
}

// CallTool admits a single externally initiated app tool without a model loop.
// Registered callers need an actual app grant; the public floor is not a grant.
func (s *Service) CallTool(ctx context.Context, p authz.Principal, agentID uuid.UUID, name string, input json.RawMessage, onStart func(dbq.Run, json.RawMessage) (json.RawMessage, error)) (tool.Result, uuid.UUID, error) {
	if onStart == nil {
		panic("capabilities: run admission callback is required")
	}
	q := dbq.New(s.db.Pool())
	run, err := execution.New(s.db).Admit(ctx, p, execution.Request{AgentID: agentID, Kind: execution.Tool, Ref: name, Input: input})
	if err != nil {
		return tool.Result{}, uuid.Nil, err
	}
	runID := uuid.UUID(run.ID.Bytes)
	callCtx, stopCall := context.WithCancel(ctx)
	defer stopCall()
	stopWatch := execution.Watch(callCtx, q, agentID, runID, stopCall)
	defer stopWatch()
	var result tool.Result
	input, invokeErr := onStart(run, input)
	if invokeErr == nil {
		result, invokeErr = s.Invoke(callCtx, Scope{AgentID: agentID, RunID: runID}, capability.Local(capability.Tool, "", name).ID(), uuid.NewString(), input)
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	status, errorMessage := "success", ""
	if invokeErr != nil {
		status = "error"
		errorMessage = invokeErr.Error()
	}
	if errors.Is(invokeErr, context.Canceled) {
		status = "cancelled"
	}
	if _, err := q.CompleteCapabilityRun(finishCtx, dbq.CompleteCapabilityRunParams{ID: run.ID, Status: status, ErrorMessage: errorMessage}); err != nil {
		invokeErr = errors.Join(invokeErr, err)
	}
	if err := q.UpdateRunLLMStats(finishCtx, run.ID); err != nil {
		invokeErr = errors.Join(invokeErr, err)
	}
	return result, runID, invokeErr
}

func (s *Service) Invoke(ctx context.Context, scope Scope, capabilityID, toolCallID string, input json.RawMessage) (result tool.Result, err error) {
	if scope.OwnerToken != uuid.Nil {
		ctx = execution.WithRuntimeOwner(ctx, scope.RunID, scope.OwnerToken)
	}
	selected := false
	// Failed tools can carry output too; revoked callers must receive neither.
	defer func() {
		if !selected {
			return
		}
		_, current, checkErr := s.resolve(ctx, scope)
		if checkErr == nil {
			for _, definition := range current {
				if definition.Path.ID() == capabilityID {
					return
				}
			}
			checkErr = service.ErrForbidden
		}
		result, err = tool.Result{}, checkErr
	}()
	if toolCallID == "" || !json.Valid(input) {
		return tool.Result{}, service.ErrInvalidInput
	}
	runtime, definitions, err := s.resolve(ctx, scope)
	if err != nil {
		return tool.Result{}, err
	}
	for _, definition := range definitions {
		if definition.Path.ID() != capabilityID {
			continue
		}
		selected = true
		switch definition.Target {
		case capability.Platform:
			return s.platform.InvokePlatform(ctx, runtime, definition, input)
		case capability.App:
			fileList := definition.Path.Kind() == capability.Air && definition.Path.CanonicalOperation() == "file_list"
			if definition.Path.Kind() == capability.Air && (runtime.Definition != nil || fileList) {
				input, err = s.scopeTaskFiles(ctx, runtime, definition.Path.CanonicalOperation(), input)
				if err != nil {
					return tool.Result{}, err
				}
			}
			if err := s.platform.ValidateAppFiles(ctx, runtime, input, definition.InputSchema); err != nil {
				return tool.Result{}, err
			}
			runtime, err = execution.IssueInvocation(ctx, dbq.New(s.db.Pool()), scope.AgentID, scope.RunID, scope.OwnerToken, time.Now().Add(5*time.Minute))
			if err != nil {
				return tool.Result{}, err
			}
			defer func(token string) {
				if closeErr := execution.CloseInvocation(dbq.New(s.db.Pool()), token); closeErr != nil {
					result, err = tool.Result{}, errors.Join(err, closeErr)
				}
			}(runtime.InvocationToken)
			response, err := s.app.InvokeRuntime(ctx, scope.AgentID, wire.RuntimeInvokeRequest{
				RuntimeProtocol: wire.AppRuntimeProtocol,
				CapabilityID:    capabilityID, ToolCallID: toolCallID, Input: input, Context: runtime,
			})
			if err != nil {
				return tool.Result{}, err
			}
			runtime, _, err = s.resolve(ctx, scope)
			if err != nil {
				return tool.Result{}, err
			}
			actions := response.Actions
			if actions == nil {
				actions = []wire.Action{}
			}
			encoded, err := json.Marshal(actions)
			if err != nil {
				return tool.Result{}, err
			}
			var logs strings.Builder
			for _, entry := range response.Logs {
				fmt.Fprintln(&logs, entry.Message)
			}
			tx, err := s.db.Pool().Begin(ctx)
			if err != nil {
				return tool.Result{}, err
			}
			defer tx.Rollback(ctx)
			q := dbq.New(tx)
			if scope.OwnerToken != uuid.Nil {
				if _, err := q.LockConversationRunLease(ctx, dbq.LockConversationRunLeaseParams{RunID: pgID(scope.RunID), OwnerToken: pgID(scope.OwnerToken)}); err != nil {
					return tool.Result{}, service.ErrConflict
				}
			}
			rows, err := q.AppendRuntimeTelemetry(ctx, dbq.AppendRuntimeTelemetryParams{
				RunID: pgID(scope.RunID), AgentID: pgID(scope.AgentID), Actions: encoded, Logs: logs.String(),
			})
			if err != nil {
				return tool.Result{}, err
			}
			if rows != 1 {
				return tool.Result{}, service.ErrConflict
			}
			if err := tx.Commit(ctx); err != nil {
				return tool.Result{}, err
			}
			if fileList && (response.Error == "" || response.Output != "") {
				var files []wire.FileInfo
				if err := json.Unmarshal([]byte(response.Output), &files); err != nil {
					return tool.Result{}, fmt.Errorf("invalid file_list output: %w", err)
				}
				allowed := files[:0]
				for _, file := range files {
					resolved, err := s.files.ResolveForRuntime(ctx, runtime, file.Path, agentstorage.OperationList)
					if errors.Is(err, service.ErrNotFound) {
						continue
					}
					if err != nil {
						return tool.Result{}, err
					}
					// A listing names physical entries, not aliases that can be
					// rewritten into the admitted user's/conversation's/run's scope.
					if resolved.Relative == file.Path {
						allowed = append(allowed, file)
					}
				}
				output, err := json.Marshal(allowed)
				if err != nil {
					return tool.Result{}, err
				}
				response.Output = string(output)
			}
			if response.Error == "" && json.Valid([]byte(response.Output)) {
				if err := s.platform.ValidateAppFiles(ctx, runtime, []byte(response.Output), definition.OutputSchema); err != nil {
					return tool.Result{}, err
				}
			}
			result := tool.Result{Output: response.Output, Title: response.Title, Metadata: response.Metadata}
			for _, attachment := range response.Attachments {
				file, err := s.files.ResolveForRuntime(ctx, runtime, attachment.Path, agentstorage.OperationRead)
				if err != nil {
					return tool.Result{}, err
				}
				result.Attachments = append(result.Attachments, tool.Attachment{
					Data: "s3ref:" + file.Relative, MimeType: attachment.MimeType, Filename: attachment.Filename,
				})
			}
			if len(response.Warnings) > 0 {
				if result.Metadata == nil {
					result.Metadata = map[string]any{}
				}
				result.Metadata["warnings"] = response.Warnings
			}
			if response.Error != "" {
				return result, errors.New(response.Error)
			}
			return result, nil
		default:
			return tool.Result{}, errors.New("executor intrinsic cannot be invoked through the broker")
		}
	}
	return tool.Result{}, service.ErrForbidden
}

func (s *Service) resolve(ctx context.Context, scope Scope) (wire.RuntimeContext, []capability.Definition, error) {
	q := dbq.New(s.db.Pool())
	resolved, err := execution.Resolve(ctx, q, scope.AgentID, scope.RunID)
	runtime, run := resolved.Runtime, resolved.Run
	if err != nil {
		return runtime, nil, err
	}
	if scope.OwnerToken != uuid.Nil {
		if _, err := q.LockConversationRunLease(ctx, dbq.LockConversationRunLeaseParams{RunID: run.ID, OwnerToken: pgID(scope.OwnerToken)}); err != nil {
			return runtime, nil, service.ErrConflict
		}
	} else if run.CallerConversationID.Valid {
		owned, err := q.IsConversationRunOwned(ctx, run.CallerConversationID)
		if err != nil {
			return runtime, nil, err
		}
		if owned {
			return runtime, nil, service.ErrConflict
		}
	}
	access := agentsdk.Access(runtime.Caller.Access)
	manifestJSON, err := q.GetRuntimeManifest(ctx, pgID(scope.AgentID))
	if err != nil {
		return runtime, nil, fmt.Errorf("app runtime manifest unavailable; rebuild the app: %w", err)
	}
	var manifest wire.AgentManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return runtime, nil, err
	}
	if err := wire.CheckAppRuntimeProtocol(manifest.RuntimeProtocol); err != nil {
		return runtime, nil, err
	}
	discovery := capability.Discovery{MCPSchemas: map[string][]wire.MCPToolSchema{}}
	servers, err := q.ListBoundMCPServersByAgent(ctx, run.AgentID)
	if err != nil {
		return runtime, nil, err
	}
	for _, server := range servers {
		var schemas []wire.MCPToolSchema
		if err := json.Unmarshal(server.ToolSchemas, &schemas); err != nil {
			return runtime, nil, err
		}
		discovery.MCPSchemas[server.Slug] = schemas
	}
	var definitions []capability.Definition
	if runtime.Definition != nil {
		definitions, err = capability.DefinitionCatalog(manifest, *runtime.Definition, discovery)
	} else {
		definitions, err = capability.Catalog(manifest, discovery)
	}
	if err != nil {
		return runtime, nil, err
	}
	allowed := make([]capability.Definition, 0, len(definitions))
	for _, definition := range definitions {
		if runtime.Definition != nil && definition.Path.Kind() == capability.Air && (definition.Path.CanonicalOperation() == "output" || definition.Path.CanonicalOperation() == "request_upgrade") {
			continue
		}
		if authz.AccessAtLeast(access, agentsdk.Access(definition.Access)) {
			allowed = append(allowed, definition)
		}
	}
	return runtime, allowed, nil
}

func pgID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// Fixed file tools execute in trusted native app code. Resolve their untrusted
// model-selected paths before dispatch so task admin access cannot bypass the
// admitted conversation/run scope. Listing roots are resolved for every run.
// Native Go resource APIs remain app-owned.
func (s *Service) scopeTaskFiles(ctx context.Context, runtime wire.RuntimeContext, operation string, input json.RawMessage) (json.RawMessage, error) {
	fields := map[string]agentstorage.Operation{}
	switch operation {
	case "file_read", "file_read_bytes", "file_read_range_bytes", "file_grep", "file_head", "file_tail", "file_lines", "file_stat", "file_exists":
		fields["path"] = agentstorage.OperationRead
	case "file_write":
		fields["path"] = agentstorage.OperationWrite
	case "file_delete":
		fields["path"] = agentstorage.OperationDelete
	case "file_list":
		fields["path"] = agentstorage.OperationList
	case "file_encode", "file_decode", "file_decode_text", "file_edit_lines", "file_sed":
		fields["src"], fields["dst"] = agentstorage.OperationRead, agentstorage.OperationWrite
	default:
		return input, nil
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, service.ErrInvalidInput
	}
	for field, op := range fields {
		var path string
		if raw := params[field]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &path); err != nil {
				return nil, service.ErrInvalidInput
			}
		}
		if path == "" && field == "dst" {
			continue
		}
		resolved, err := s.files.ResolveForRuntime(ctx, runtime, path, op)
		if err != nil {
			return nil, err
		}
		params[field], err = json.Marshal(resolved.Relative)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(params)
}
