package agentruns

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/agentruntime"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrBudget = execution.ErrAgentBudget

type controller struct {
	service        *Service
	app, id, token uuid.UUID
}

func (c *controller) owner(ctx context.Context, q *dbq.Queries) (dbq.AgentTaskCall, error) {
	if _, err := execution.Resolve(ctx, q, c.app, c.id); err != nil {
		return dbq.AgentTaskCall{}, err
	}
	return q.LockAgentTaskOwner(ctx, dbq.LockAgentTaskOwnerParams{ID: pgID(c.id), OwnerToken: pgID(c.token)})
}

func exhausted(c dbq.AgentTaskCall) bool {
	return c.StepLimit > 0 && c.Steps >= c.StepLimit || c.TokenLimit > 0 && c.Tokens >= c.TokenLimit || c.Deadline.Valid && !time.Now().Before(c.Deadline.Time)
}

func (c *controller) BeforeModel(ctx context.Context) error {
	return execution.ReserveAgentTaskStep(ctx, c.service.db, c.app, c.id, c.token)
}

func (c *controller) Spawn(ctx context.Context, toolID, slug string, input json.RawMessage) (wire.AgentRunInfo, error) {
	return c.launch(ctx, toolID, slug, "", input, "")
}
func (c *controller) Continue(ctx context.Context, toolID, sessionID, prompt string) (wire.AgentRunInfo, error) {
	return c.launch(ctx, toolID, "", sessionID, nil, prompt)
}
func (c *controller) launch(ctx context.Context, toolID, slug, sessionID string, input json.RawMessage, prompt string) (wire.AgentRunInfo, error) {
	if strings.TrimSpace(toolID) == "" {
		return wire.AgentRunInfo{}, service.ErrInvalidInput
	}
	tx, q, err := c.service.transaction(ctx)
	if err != nil {
		return wire.AgentRunInfo{}, err
	}
	defer tx.Rollback(ctx)
	parent, err := c.owner(ctx, q)
	if err != nil {
		return wire.AgentRunInfo{}, err
	}
	if parent.ParentID.Valid {
		return wire.AgentRunInfo{}, service.ErrForbidden
	}
	var sid uuid.UUID
	if sessionID != "" {
		sid, err = parseID(sessionID)
		if err != nil {
			return wire.AgentRunInfo{}, err
		}
		calls, err := q.ListAgentTaskSessionCalls(ctx, pgID(sid))
		if err != nil {
			return wire.AgentRunInfo{}, err
		}
		if len(calls) == 0 || calls[0].ParentID != parent.ID || calls[0].AgentID != parent.AgentID {
			return wire.AgentRunInfo{}, service.ErrNotFound
		}
		slug = calls[0].Definition
	}
	var contract wire.AgentDefinition
	if err := json.Unmarshal(parent.DefinitionSnapshot, &contract); err != nil {
		return wire.AgentRunInfo{}, err
	}
	if !slices.Contains(contract.Subagents, slug) {
		return wire.AgentRunInfo{}, service.ErrForbidden
	}
	prior, priorErr := q.GetAgentTaskSpawn(ctx, dbq.GetAgentTaskSpawnParams{ParentID: parent.ID, ParentToolCallID: toText(toolID)})
	if priorErr != nil && !errors.Is(priorErr, pgx.ErrNoRows) {
		return wire.AgentRunInfo{}, priorErr
	}
	child := wire.AgentDefinition{ContractHash: prior.ContractHash}
	if errors.Is(priorErr, pgx.ErrNoRows) {
		var declared []wire.AgentDefinition
		if err := json.Unmarshal(parent.SubagentSnapshots, &declared); err != nil {
			return wire.AgentRunInfo{}, err
		}
		expected := ""
		for _, d := range declared {
			if d.Slug == slug {
				expected = d.ContractHash
				break
			}
		}
		if expected == "" {
			return wire.AgentRunInfo{}, service.ErrConflict
		}
		child, err = definition(ctx, q, c.app, slug, expected)
		if err != nil {
			return wire.AgentRunInfo{}, err
		}
	}
	var payload []byte
	message := string(input)
	if sessionID == "" {
		payload, err = json.Marshal(wire.StartAgentRequest{RequestID: toolID, ContractHash: child.ContractHash, Input: input})
	} else {
		message = prompt
		payload, err = json.Marshal(struct {
			SessionID string `json:"sessionId"`
			Prompt    string `json:"prompt"`
			Hash      string `json:"contractHash"`
		}{sessionID, prompt, child.ContractHash})
	}
	if err != nil {
		return wire.AgentRunInfo{}, service.ErrInvalidInput
	}
	if priorErr == nil {
		if prior.Definition != slug || !equalJSON(prior.RequestPayload, payload) {
			return wire.AgentRunInfo{}, service.ErrConflict
		}
		return runInfo(prior)
	}
	if exhausted(parent) {
		return wire.AgentRunInfo{}, ErrBudget
	}
	// UUID namespacing cannot collide with a sibling's tool call ID or a native
	// request. The separate parent/tool uniqueness constraint is authoritative.
	key := "child:" + uuid.NewSHA1(c.id, []byte(toolID)).String()
	call, _, err := c.service.create(ctx, q, c.app, slug, child.ContractHash, key, input, message, payload, sid, &parent, toolID)
	if err != nil {
		return wire.AgentRunInfo{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return wire.AgentRunInfo{}, err
	}
	return runInfo(call)
}

func (c *controller) children(ctx context.Context, q *dbq.Queries, ids []string) ([]dbq.AgentTaskCall, error) {
	if len(ids) == 0 || len(ids) > 100 {
		return nil, service.ErrInvalidInput
	}
	out := make([]dbq.AgentTaskCall, 0, len(ids))
	seen := map[uuid.UUID]bool{}
	for _, raw := range ids {
		id, err := parseID(raw)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			return nil, service.ErrInvalidInput
		}
		seen[id] = true
		row, err := q.GetAgentTaskCall(ctx, pgID(id))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, service.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if row.AgentID != pgID(c.app) || row.ParentID != pgID(c.id) {
			return nil, service.ErrNotFound
		}
		out = append(out, row)
	}
	return out, nil
}

func (c *controller) Get(ctx context.Context, ids []string) ([]wire.AgentRunInfo, error) {
	tx, q, err := c.service.transaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := c.owner(ctx, q); err != nil {
		return nil, err
	}
	rows, err := c.children(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	out := make([]wire.AgentRunInfo, 0, len(rows))
	for _, r := range rows {
		info, err := runInfo(r)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

func (c *controller) Wait(ctx context.Context, toolID string, req wire.AgentWaitRequest) (wire.AgentWaitResult, error) {
	out := wire.AgentWaitResult{Completed: []wire.AgentRunInfo{}, Pending: []string{}}
	if toolID == "" || req.Mode != "any" && req.Mode != "all" {
		return out, service.ErrInvalidInput
	}
	timeout := c.service.config.DefaultWait
	if req.TimeoutMS != nil {
		if *req.TimeoutMS < 0 || *req.TimeoutMS > c.service.config.MaxWait.Milliseconds() {
			return out, service.ErrInvalidInput
		}
		timeout = time.Duration(*req.TimeoutMS) * time.Millisecond
	}
	tx, q, err := c.service.transaction(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	if _, err := c.owner(ctx, q); err != nil {
		return out, err
	}
	rows, err := c.children(ctx, q, req.IDs)
	if err != nil {
		return out, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	wait, err := q.GetAgentTaskWait(ctx, pgID(c.id))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	fresh := err != nil || wait.ToolCallID != toolID
	if err == nil && wait.ToolCallID == toolID {
		if !equalJSON(wait.Request, payload) {
			return out, service.ErrConflict
		}
	} else {
		if err := q.DeleteAgentTaskWait(ctx, pgID(c.id)); err != nil {
			return out, err
		}
		wait, err = q.CreateAgentTaskWait(ctx, dbq.CreateAgentTaskWaitParams{RunID: pgID(c.id), ToolCallID: toolID, Request: payload, Deadline: timestamp(time.Now().Add(timeout))})
		if err != nil {
			return out, err
		}
		for _, row := range rows {
			if err := q.AddAgentTaskWaitDependency(ctx, dbq.AddAgentTaskWaitDependencyParams{RunID: pgID(c.id), DependencyID: row.ID}); err != nil {
				return out, err
			}
		}
	}
	for _, row := range rows {
		if row.CompletedAt.Valid {
			info, err := runInfo(row)
			if err != nil {
				return out, err
			}
			out.Completed = append(out.Completed, info)
		} else {
			out.Pending = append(out.Pending, uuid.UUID(row.ID.Bytes).String())
		}
	}
	ready := len(out.Pending) == 0 || req.Mode == "any" && len(out.Completed) > 0
	if ready {
		out.Reason = "ready"
	} else if (!fresh || timeout == 0) && !time.Now().Before(wait.Deadline.Time) {
		out.Reason = "timeout"
	}
	// A positive new wait yields once even if DB writes consumed its timeout.
	// Explicit zero-duration polls remain non-parking operations.
	if err := tx.Commit(ctx); err != nil {
		return out, err
	}
	if out.Reason == "" {
		return out, agentruntime.ErrWaiting
	}
	return out, nil
}

func (c *controller) Cancel(ctx context.Context, ids []string) (wire.AgentCancelResult, error) {
	out := wire.AgentCancelResult{Calls: []wire.AgentRunInfo{}}
	tx, q, err := c.service.transaction(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	if _, err := c.owner(ctx, q); err != nil {
		return out, err
	}
	rows, err := c.children(ctx, q, ids)
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		if err := q.RequestAgentTaskCancellation(ctx, row.ID); err != nil {
			return out, err
		}
		info, err := runInfo(row)
		if err != nil {
			return out, err
		}
		out.Calls = append(out.Calls, info)
	}
	return out, tx.Commit(ctx)
}

func (c *controller) Complete(ctx context.Context, reply wire.AgentReply) error {
	tx, q, err := c.service.transaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	call, err := c.owner(ctx, q)
	if err != nil {
		return err
	}
	var d wire.AgentDefinition
	if err := json.Unmarshal(call.DefinitionSnapshot, &d); err != nil {
		return err
	}
	switch reply.Kind {
	case "output":
		if reply.Question != "" {
			return service.ErrInvalidInput
		}
		if err := validateValue(d.OutputSchema, reply.Output); err != nil {
			return err
		}
	case "needs_input":
		if strings.TrimSpace(reply.Question) == "" || len(reply.Output) != 0 {
			return service.ErrInvalidInput
		}
	default:
		return service.ErrInvalidInput
	}
	children, err := q.ListAgentTaskChildren(ctx, call.ID)
	if err != nil {
		return err
	}
	for _, child := range children {
		if !child.CompletedAt.Valid {
			return service.Detail(service.ErrConflict, "active children must finish before completion")
		}
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	if len(call.Reply) != 0 && !equalJSON(call.Reply, raw) {
		return service.ErrConflict
	}
	if err := q.SaveAgentTaskReply(ctx, dbq.SaveAgentTaskReplyParams{ID: call.ID, Reply: raw}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var _ agentruntime.Controller = (*controller)(nil)
