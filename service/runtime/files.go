package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/airlockrun/agentsdk/wire"
	agentstorage "github.com/airlockrun/airlock/service/agentstorage"
)

func (h *Service) ValidateAppFiles(ctx context.Context, scope wire.RuntimeContext, input, schemaJSON json.RawMessage) error {
	schema, err := ParseSchema(schemaJSON)
	if err != nil || !SchemaHasAgentMarker(schema) {
		return nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	_, problem := WalkSchema(value, schema, "", func(format string, value any, _ string) (any, *MaterializeError) {
		if value == nil {
			return nil, nil
		}
		path, ok := value.(string)
		if !ok {
			return nil, &MaterializeError{Code: RpcErrInvalidParams, Message: "file reference must be a stored path"}
		}
		op := agentstorage.OperationRead
		if format == "agent-dir" {
			op = agentstorage.OperationList
		}
		if _, err := h.files.ResolveForRuntime(ctx, scope, path, op); err != nil {
			return nil, &MaterializeError{Code: RpcErrInvalidParams, Message: "file reference is not accessible"}
		}
		return value, nil
	})
	if problem != nil {
		return errors.New(problem.Message)
	}
	return nil
}
