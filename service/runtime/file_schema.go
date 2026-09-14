package runtime

import (
	"encoding/json"
	"fmt"
)

// materializeError carries a JSON-RPC error code + human-readable
// message back to the dispatcher. Caller wraps via writeJSONRPCError.
type MaterializeError struct {
	Code    int
	Message string
}

// --- Walker ---

// walkSchema traverses value in parallel with schema. At each leaf where
// schema declares format=agent-file or agent-dir, fn is called. ptr is a
// dotted JSON pointer for error messages.
func WalkSchema(value any, schema map[string]any, ptr string, fn func(format string, v any, ptr string) (any, *MaterializeError)) (any, *MaterializeError) {
	if schema == nil {
		return value, nil
	}
	// goai/schema emits nullable as {anyOf: [T, {type:"null"}]} — pick T
	// when the value is non-null so format markers carry through.
	if anyOf, ok := schema["anyOf"].([]any); ok && len(anyOf) == 2 && value != nil {
		for _, alt := range anyOf {
			altMap, _ := alt.(map[string]any)
			if t, _ := altMap["type"].(string); t != "null" {
				schema = altMap
				break
			}
		}
	}

	format, _ := schema["format"].(string)
	schemaType, _ := schema["type"].(string)

	if format == "agent-file" || format == "agent-dir" {
		if value == nil {
			return value, nil
		}
		return fn(format, value, ptr)
	}

	switch schemaType {
	case "object":
		m, ok := value.(map[string]any)
		if !ok {
			return value, nil
		}
		props, _ := schema["properties"].(map[string]any)
		for name, propRaw := range props {
			propSchema, _ := propRaw.(map[string]any)
			if v, has := m[name]; has {
				rew, err := WalkSchema(v, propSchema, ptr+"."+name, fn)
				if err != nil {
					return nil, err
				}
				m[name] = rew
			}
		}
		return m, nil
	case "array":
		arr, ok := value.([]any)
		if !ok {
			return value, nil
		}
		itemSchema, _ := schema["items"].(map[string]any)
		for i, item := range arr {
			rew, err := WalkSchema(item, itemSchema, fmt.Sprintf("%s[%d]", ptr, i), fn)
			if err != nil {
				return nil, err
			}
			arr[i] = rew
		}
		return arr, nil
	}
	return value, nil
}

// --- Helpers ---

// parseSchema returns the schema as a parsed map. Empty / unparseable
// schemas yield (nil, nil) so callers can fast-path through.
func ParseSchema(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// schemaHasAgentMarker walks the schema tree once looking for any
// format=agent-file or agent-dir marker. Lets us skip the full
// args/result walk for the common no-FilePath tool.
func SchemaHasAgentMarker(schema map[string]any) bool {
	if schema == nil {
		return false
	}
	if f, _ := schema["format"].(string); f == "agent-file" || f == "agent-dir" {
		return true
	}
	if props, ok := schema["properties"].(map[string]any); ok {
		for _, v := range props {
			if m, ok := v.(map[string]any); ok && SchemaHasAgentMarker(m) {
				return true
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		if SchemaHasAgentMarker(items) {
			return true
		}
	}
	if anyOf, ok := schema["anyOf"].([]any); ok {
		for _, alt := range anyOf {
			if m, ok := alt.(map[string]any); ok && SchemaHasAgentMarker(m) {
				return true
			}
		}
	}
	return false
}
