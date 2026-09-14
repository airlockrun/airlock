// Package agentruns owns durable application task sessions, hierarchical calls,
// scheduling and budgets. Database leases, not process-local worker state, confer
// authority to execute a task.
package agentruns

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/agentruntime"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/capabilities"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"go.uber.org/zap"
)

type Backend interface {
	PrepareAgent(context.Context, capabilities.Scope, wire.AgentDefinition) (agentruntime.Input, error)
}

type Config struct {
	GlobalConcurrency int
	LocalConcurrency  int
	DefaultWait       time.Duration
	MaxWait           time.Duration
}

type Service struct {
	db        *db.DB
	broker    *capabilities.Service
	backend   Backend
	executors container.JSExecutorManager
	logger    *zap.Logger
	config    Config
}

func New(database *db.DB, broker *capabilities.Service, backend Backend, executors container.JSExecutorManager, logger *zap.Logger, config Config) *Service {
	if database == nil || broker == nil || backend == nil || executors == nil || logger == nil {
		panic("agentruns: all dependencies are required")
	}
	if config.GlobalConcurrency <= 0 || config.LocalConcurrency <= 0 || config.DefaultWait <= 0 || config.MaxWait < config.DefaultWait {
		panic("agentruns: positive concurrency and bounded wait configuration are required")
	}
	return &Service{db: database, broker: broker, backend: backend, executors: executors, logger: logger, config: config}
}

func (s *Service) transaction(ctx context.Context) (pgx.Tx, *dbq.Queries, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	q := dbq.New(tx)
	if err := q.LockAgentTaskScheduler(ctx); err != nil {
		tx.Rollback(ctx)
		return nil, nil, err
	}
	return tx, q, nil
}

func admit(ctx context.Context, q *dbq.Queries) (uuid.UUID, error) {
	id := auth.AgentIDFromContext(ctx)
	if err := authz.Authorize(ctx, q, authz.TriggerPrincipal(), authz.AppRuntime, id); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func definition(ctx context.Context, q *dbq.Queries, app uuid.UUID, slug, hash string) (wire.AgentDefinition, error) {
	raw, err := q.GetRuntimeManifest(ctx, pgID(app))
	if err != nil {
		return wire.AgentDefinition{}, service.Detail(service.ErrConflict, "current app manifest unavailable; rebuild and synchronize the app")
	}
	var manifest wire.AgentManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return wire.AgentDefinition{}, err
	}
	if err := wire.CheckAppRuntimeProtocol(manifest.RuntimeProtocol); err != nil {
		return wire.AgentDefinition{}, service.Detail(service.ErrConflict, "%s", err)
	}
	if err := wire.ValidateAgentDefinitions(manifest); err != nil {
		return wire.AgentDefinition{}, service.Detail(service.ErrConflict, "%s", err)
	}
	for _, d := range manifest.AgentDefinitions {
		if d.Slug == slug {
			if hash != "" && hash != d.ContractHash {
				return d, service.Detail(service.ErrConflict, "agent definition contract is incompatible; rebuild the app")
			}
			return d, nil
		}
	}
	return wire.AgentDefinition{}, service.ErrNotFound
}

func validateValue(schema, raw json.RawMessage) error {
	c := jsonschema.NewCompiler()
	c.LoadURL = func(string) (io.ReadCloser, error) {
		return nil, errors.New("external schema references are not allowed")
	}
	if err := c.AddResource("urn:airlock:agent", bytes.NewReader(schema)); err != nil {
		return service.Detail(service.ErrInvalidInput, "invalid schema: %s", err)
	}
	compiled, err := c.Compile("urn:airlock:agent")
	if err != nil {
		return service.Detail(service.ErrInvalidInput, "invalid schema: %s", err)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return service.ErrInvalidInput
	}
	if !json.Valid(raw) {
		return service.ErrInvalidInput
	}
	if err := compiled.Validate(value); err != nil {
		return service.Detail(service.ErrInvalidInput, "input does not match the agent contract: %s", err)
	}
	return nil
}

func (s *Service) Start(ctx context.Context, slug string, req wire.StartAgentRequest) (wire.AgentRunResponse, error) {
	tx, q, err := s.transaction(ctx)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	defer tx.Rollback(ctx)
	app, err := admit(ctx, q)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return wire.AgentRunResponse{}, service.ErrInvalidInput
	}
	call, created, err := s.create(ctx, q, app, slug, req.ContractHash, req.RequestID, req.Input, string(req.Input), payload, uuid.Nil, nil, "")
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return wire.AgentRunResponse{}, err
	}
	return response(call, created)
}

func (s *Service) Continue(ctx context.Context, slug, sessionID string, req wire.ContinueAgentRequest) (wire.AgentRunResponse, error) {
	id, err := parseID(sessionID)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	tx, q, err := s.transaction(ctx)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	defer tx.Rollback(ctx)
	app, err := admit(ctx, q)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	payload, err := json.Marshal(struct {
		SessionID string                    `json:"sessionId"`
		Request   wire.ContinueAgentRequest `json:"request"`
	}{sessionID, req})
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	call, created, err := s.create(ctx, q, app, slug, req.ContractHash, req.RequestID, nil, req.Prompt, payload, id, nil, "")
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return wire.AgentRunResponse{}, err
	}
	return response(call, created)
}

// create runs under the scheduler lock. Request keys belong to the app and
// definition, independently of the native SDK's source execution context.
func (s *Service) create(ctx context.Context, q *dbq.Queries, app uuid.UUID, slug, hash, requestID string, input json.RawMessage, message string, payload []byte, sessionID uuid.UUID, parent *dbq.AgentTaskCall, toolID string) (dbq.AgentTaskCall, bool, error) {
	if strings.TrimSpace(requestID) == "" || len(requestID) > 256 || hash == "" || strings.TrimSpace(message) == "" || len(payload) > 1<<20 {
		return dbq.AgentTaskCall{}, false, service.ErrInvalidInput
	}
	prior, err := q.GetAgentTaskRequest(ctx, dbq.GetAgentTaskRequestParams{AgentID: pgID(app), Definition: slug, RequestID: requestID})
	if err == nil {
		if !equalJSON(prior.RequestPayload, payload) || prior.ParentToolCallID.String != toolID || (parent == nil) != !prior.ParentID.Valid || parent != nil && prior.ParentID != parent.ID {
			return prior, false, service.ErrConflict
		}
		return prior, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return prior, false, err
	}
	d, err := definition(ctx, q, app, slug, hash)
	if err != nil {
		return prior, false, err
	}
	if sessionID == uuid.Nil {
		if err := validateValue(d.InputSchema, input); err != nil {
			return prior, false, err
		}
		conv, err := q.CreateAgentTaskConversation(ctx, dbq.CreateAgentTaskConversationParams{AgentID: pgID(app), Title: slug})
		if err != nil {
			return prior, false, err
		}
		sessionID = uuid.UUID(conv.ID.Bytes)
		if _, err := q.CreateAgentTaskSession(ctx, dbq.CreateAgentTaskSessionParams{ID: conv.ID, AgentID: pgID(app), Definition: slug, ContractHash: hash}); err != nil {
			return prior, false, err
		}
	} else {
		session, err := q.GetAgentTaskSession(ctx, dbq.GetAgentTaskSessionParams{ID: pgID(sessionID), AgentID: pgID(app), Definition: slug})
		if errors.Is(err, pgx.ErrNoRows) {
			return prior, false, service.ErrNotFound
		}
		if err != nil {
			return prior, false, err
		}
		if session.ContractHash != hash {
			return prior, false, service.ErrConflict
		}
		calls, err := q.ListAgentTaskSessionCalls(ctx, session.ID)
		if err != nil {
			return prior, false, err
		}
		if len(calls) == 0 || calls[0].Status != "completed" {
			return prior, false, service.Detail(service.ErrConflict, "session must have a completed run and no active call")
		}
		if parent != nil && calls[0].ParentID != parent.ID {
			return prior, false, service.ErrForbidden
		}
		if parent == nil && calls[0].ParentID.Valid {
			return prior, false, service.ErrForbidden
		}
	}
	appRow, err := q.GetAgentByIDForUpdate(ctx, pgID(app))
	if err != nil {
		return prior, false, err
	}
	if parent != nil {
		if _, err := execution.Resolve(execution.WithRuntimeOwner(ctx, uuid.UUID(parent.ID.Bytes), uuid.UUID(parent.OwnerToken.Bytes)), q, app, uuid.UUID(parent.ID.Bytes)); err != nil {
			return prior, false, err
		}
	}
	d, err = definition(ctx, q, app, slug, hash)
	if err != nil {
		return prior, false, err
	}
	run, err := execution.AdmitAgentTx(ctx, q, app, appRow.AgentTokenVersion, sessionID, slug, payload)
	if err != nil {
		return prior, false, err
	}
	snapshot, err := json.Marshal(d)
	if err != nil {
		return prior, false, err
	}
	subagents := make([]wire.AgentDefinition, 0, len(d.Subagents))
	for _, slug := range d.Subagents {
		child, err := definition(ctx, q, app, slug, "")
		if err != nil {
			return prior, false, err
		}
		subagents = append(subagents, child)
	}
	subagentSnapshots, err := json.Marshal(subagents)
	if err != nil {
		return prior, false, err
	}
	params := dbq.CreateAgentTaskCallParams{ID: run.ID, SessionID: pgID(sessionID), AgentID: pgID(app), Definition: slug, ContractHash: hash, DefinitionSnapshot: snapshot, RequestID: requestID, RequestPayload: payload, Message: message, RootID: run.ID, StepLimit: d.Budget.Steps, TokenLimit: d.Budget.Tokens, MaxAttempts: d.MaxAttempts, MaxConcurrency: d.MaxConcurrency, MaxSubagentCalls: d.MaxSubagentCalls, MaxConcurrentSubagents: d.MaxConcurrentSubagents, RuntimeGeneration: appRow.AgentTokenVersion}
	params.SubagentSnapshots = subagentSnapshots
	if d.Budget.TimeoutMS > 0 {
		if d.Budget.TimeoutMS > int64((1<<63-1)/int64(time.Millisecond)) {
			return prior, false, service.ErrInvalidInput
		}
		params.Deadline = timestamp(time.Now().Add(time.Duration(d.Budget.TimeoutMS) * time.Millisecond))
	}
	if parent != nil {
		if parent.ParentID.Valid || parent.CancelRequestedAt.Valid {
			return prior, false, service.ErrForbidden
		}
		children, err := q.ListAgentTaskChildren(ctx, parent.ID)
		if err != nil {
			return prior, false, err
		}
		active := 0
		for _, c := range children {
			if !c.CompletedAt.Valid {
				active++
			}
		}
		if len(children) >= int(parent.MaxSubagentCalls) || active >= int(parent.MaxConcurrentSubagents) {
			return prior, false, service.Detail(service.ErrConflict, "subagent call limit reached")
		}
		params.ParentID, params.RootID, params.ParentToolCallID = parent.ID, parent.RootID, pgtype.Text{String: toolID, Valid: true}
		if parent.Deadline.Valid && (!params.Deadline.Valid || parent.Deadline.Time.Before(params.Deadline.Time)) {
			params.Deadline = parent.Deadline
		}
	}
	call, err := q.CreateAgentTaskCall(ctx, params)
	return call, true, err
}

func (s *Service) Get(ctx context.Context, slug, id string) (wire.AgentRunResponse, error) {
	runID, err := parseID(id)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	q := dbq.New(s.db.Pool())
	app, err := admit(ctx, q)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	call, err := q.GetScopedAgentTaskCall(ctx, dbq.GetScopedAgentTaskCallParams{ID: pgID(runID), AgentID: pgID(app), Definition: slug})
	if errors.Is(err, pgx.ErrNoRows) {
		err = service.ErrNotFound
	}
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	return response(call, false)
}

func (s *Service) Cancel(ctx context.Context, slug, id string) (wire.AgentRunResponse, error) {
	runID, err := parseID(id)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	tx, q, err := s.transaction(ctx)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	defer tx.Rollback(ctx)
	app, err := admit(ctx, q)
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	call, err := q.GetScopedAgentTaskCall(ctx, dbq.GetScopedAgentTaskCallParams{ID: pgID(runID), AgentID: pgID(app), Definition: slug})
	if errors.Is(err, pgx.ErrNoRows) {
		err = service.ErrNotFound
	}
	if err != nil {
		return wire.AgentRunResponse{}, err
	}
	if err := q.RequestAgentTaskCancellation(ctx, call.ID); err != nil {
		return wire.AgentRunResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return wire.AgentRunResponse{}, err
	}
	return response(call, false)
}

type ListOptions struct {
	Limit                     int32
	Cursor, Status, SessionID string
	ContractHash              string
}

func (s *Service) List(ctx context.Context, slug string, opts ListOptions) (wire.ListAgentRunsResponse, error) {
	out := wire.ListAgentRunsResponse{Runs: []wire.AgentRunInfo{}}
	q := dbq.New(s.db.Pool())
	app, err := admit(ctx, q)
	if err != nil {
		return out, err
	}
	if opts.Limit == 0 {
		opts.Limit = 25
	}
	if opts.Limit < 1 || opts.Limit > 100 {
		return out, service.ErrInvalidInput
	}
	switch opts.Status {
	case "", "queued", "running", "waiting", "completed", "failed", "cancelled", "budget_exceeded":
	default:
		return out, service.ErrInvalidInput
	}
	if opts.ContractHash != "" {
		hash, err := hex.DecodeString(opts.ContractHash)
		if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != opts.ContractHash {
			return out, service.ErrInvalidInput
		}
	}
	params := dbq.ListAgentTaskCallsParams{AgentID: pgID(app), Definition: slug, Status: opts.Status, Lim: opts.Limit + 1, ContractHash: opts.ContractHash}
	if opts.SessionID != "" {
		id, err := parseID(opts.SessionID)
		if err != nil {
			return out, err
		}
		params.SessionID = pgID(id)
	}
	if opts.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(opts.Cursor)
		if err != nil {
			return out, service.ErrInvalidInput
		}
		t, id, ok := strings.Cut(string(raw), "|")
		if !ok {
			return out, service.ErrInvalidInput
		}
		at, err := time.Parse(time.RFC3339Nano, t)
		if err != nil {
			return out, service.ErrInvalidInput
		}
		cursorID, err := parseID(id)
		if err != nil {
			return out, err
		}
		params.CursorTime, params.CursorID = timestamp(at), pgID(cursorID)
	}
	rows, err := q.ListAgentTaskCalls(ctx, params)
	if err != nil {
		return out, err
	}
	if len(rows) > int(opts.Limit) {
		rows = rows[:opts.Limit]
		last := rows[len(rows)-1]
		out.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(last.CreatedAt.Time.Format(time.RFC3339Nano) + "|" + uuid.UUID(last.ID.Bytes).String()))
	}
	for _, row := range rows {
		info, err := runInfo(row)
		if err != nil {
			return out, err
		}
		out.Runs = append(out.Runs, info)
	}
	return out, nil
}

func runInfo(c dbq.AgentTaskCall) (wire.AgentRunInfo, error) {
	r := wire.AgentRunInfo{ID: uuid.UUID(c.ID.Bytes).String(), SessionID: uuid.UUID(c.SessionID.Bytes).String(), Definition: c.Definition, ContractHash: c.ContractHash, Status: c.Status, Error: c.Error, Steps: c.Steps, Tokens: c.Tokens, CreatedAt: c.CreatedAt.Time, UpdatedAt: c.UpdatedAt.Time}
	if c.StartedAt.Valid {
		r.StartedAt = &c.StartedAt.Time
	}
	if c.CompletedAt.Valid {
		r.CompletedAt = &c.CompletedAt.Time
	}
	if c.Status == "completed" {
		if len(c.Reply) == 0 {
			return r, errors.New("completed agent call has no durable reply")
		}
		if err := json.Unmarshal(c.Reply, &r.Reply); err != nil {
			return r, fmt.Errorf("invalid durable agent reply: %w", err)
		}
	}
	return r, nil
}
func response(c dbq.AgentTaskCall, created bool) (wire.AgentRunResponse, error) {
	r, err := runInfo(c)
	return wire.AgentRunResponse{Run: r, Created: created}, err
}
func pgID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil} }
func parseID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, service.ErrInvalidInput
	}
	return id, nil
}
func timestamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
func toText(s string) pgtype.Text              { return pgtype.Text{String: s, Valid: s != ""} }
func equalJSON(a, b []byte) bool {
	var x, y any
	da, db := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	da.UseNumber()
	db.UseNumber()
	if da.Decode(&x) != nil || db.Decode(&y) != nil {
		return false
	}
	// JSONB normalizes exponent notation. Preserve exact large numbers while
	// comparing numerical values, not the spelling of their JSON literals.
	var normalize func(any) any
	normalize = func(v any) any {
		switch value := v.(type) {
		case json.Number:
			r, ok := new(big.Rat).SetString(string(value))
			if !ok {
				return value
			}
			return r
		case map[string]any:
			for k, v := range value {
				value[k] = normalize(v)
			}
		case []any:
			for i, v := range value {
				value[i] = normalize(v)
			}
		}
		return v
	}
	return reflect.DeepEqual(normalize(x), normalize(y))
}
