package sysagent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// runTools wires the run-introspection + cancel tools.
func (s *Service) runTools() []tool.Tool {
	return []tool.Tool{
		s.toolListRuns(),
		s.toolGetRun(),
		s.toolGetRunLogs(),
		s.toolCancelRun(),
	}
}

// --- list_runs ---

type listRunsInput struct {
	Agent  string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	Cursor string `json:"cursor,omitempty" jsonschema:"description=RFC3339 timestamp from a previous page's next_cursor. Empty fetches the newest page."`
	Limit  int32  `json:"limit,omitempty" jsonschema:"description=Page size (1-100; defaults to 25)."`
}

func (s *Service) toolListRuns() tool.Tool {
	return tool.New("list_runs").
		Description(`List runs for the agent, newest first. Paginated by started_at — pass next_cursor from the previous response to fetch the next page. Default limit 25.`).
		SchemaFromStruct(listRunsInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in listRunsInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			var cursor time.Time
			if in.Cursor != "" {
				cursor, err = time.Parse(time.RFC3339Nano, in.Cursor)
				if err != nil {
					return errResult(service.Detail(service.ErrInvalidInput, "invalid cursor: %s", err.Error())), nil
				}
			}
			limit := in.Limit
			if limit <= 0 {
				limit = 25
			}
			if limit > 100 {
				limit = 100
			}
			out, err := s.runs.List(ctx, p, uuid.UUID(a.ID.Bytes), cursor, limit)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- get_run ---

type runIDInput struct {
	RunID string `json:"run_id" jsonschema:"required,description=Run UUID."`
}

func (s *Service) toolGetRun() tool.Tool {
	return tool.New("get_run").
		Description(`Return one run row plus the messages produced during it.`).
		SchemaFromStruct(runIDInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in runIDInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			id, err := resolveUUID("run_id", in.RunID)
			if err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			out, err := s.runs.Get(ctx, p, id)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- get_run_logs ---

func (s *Service) toolGetRunLogs() tool.Tool {
	return tool.New("get_run_logs").
		Description(`Return the captured stdout log for one run. Large logs get truncated at the 8 KiB tool-output cap — the response footer notes the true size if so.`).
		SchemaFromStruct(runIDInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in runIDInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			id, err := resolveUUID("run_id", in.RunID)
			if err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			logs, err := s.runs.Logs(ctx, p, id)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"run_id": id.String(), "logs": logs})
		}).
		Build()
}

// --- cancel_run ---

func (s *Service) toolCancelRun() tool.Tool {
	return tool.New("cancel_run").
		Description(`Cancel a running run. Allowed for agent admins, or the owner of the run's conversation when the run was a web prompt. Returns ErrConflict if the run is already in a terminal state.`).
		SchemaFromStruct(runIDInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in runIDInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			id, err := resolveUUID("run_id", in.RunID)
			if err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			if err := s.runs.Cancel(ctx, p, id); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "cancelled", "run_id": id.String()})
		}).
		Build()
}
