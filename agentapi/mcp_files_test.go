package agentapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSchemaHasAgentMarker(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"none", `{"type":"object","properties":{"name":{"type":"string"}}}`, false},
		{"top-level-file", `{"type":"string","format":"agent-file"}`, true},
		{"nested-file", `{"type":"object","properties":{"file":{"type":"string","format":"agent-file"}}}`, true},
		{"array-of-files", `{"type":"array","items":{"type":"string","format":"agent-file"}}`, true},
		{"nullable-file", `{"anyOf":[{"type":"string","format":"agent-file"},{"type":"null"}]}`, true},
		{"deep-dir", `{"type":"object","properties":{"x":{"type":"object","properties":{"d":{"type":"string","format":"agent-dir"}}}}}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var schema map[string]any
			if err := json.Unmarshal([]byte(tc.raw), &schema); err != nil {
				t.Fatalf("decode schema: %v", err)
			}
			if got := schemaHasAgentMarker(schema); got != tc.want {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestWalkSchemaAgentDirRejected(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"dir": map[string]any{"type": "string", "format": "agent-dir"},
		},
	}
	value := map[string]any{"dir": "uploads/"}
	_, err := walkSchema(value, schema, "", func(format string, v any, ptr string) (any, *materializeError) {
		if format != "agent-dir" {
			t.Fatalf("expected agent-dir format, got %q", format)
		}
		return nil, &materializeError{Code: rpcErrInvalidParams, Message: "dir not supported at " + ptr}
	})
	if err == nil {
		t.Fatal("expected error for agent-dir")
	}
	if !strings.Contains(err.Message, ".dir") {
		t.Errorf("expected ptr `.dir` in message, got %q", err.Message)
	}
}

func TestWalkSchemaNestedAndArrays(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"file":  map[string]any{"type": "string", "format": "agent-file"},
			"name":  map[string]any{"type": "string"},
			"files": map[string]any{"type": "array", "items": map[string]any{"type": "string", "format": "agent-file"}},
			"opt":   map[string]any{"anyOf": []any{map[string]any{"type": "string", "format": "agent-file"}, map[string]any{"type": "null"}}},
		},
	}
	value := map[string]any{
		"file":  "uploads/a.png",
		"name":  "alice",
		"files": []any{"uploads/b.png", "uploads/c.png"},
		"opt":   "uploads/d.png",
	}
	seen := []string{}
	rew, err := walkSchema(value, schema, "", func(format string, v any, ptr string) (any, *materializeError) {
		if format != "agent-file" {
			t.Errorf("unexpected format %q at %s", format, ptr)
		}
		seen = append(seen, ptr+"="+v.(string))
		return "REWROTE:" + v.(string), nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	got := rew.(map[string]any)
	if got["file"] != "REWROTE:uploads/a.png" {
		t.Errorf("file not rewritten: %v", got["file"])
	}
	if got["name"] != "alice" {
		t.Errorf("plain string mutated: %v", got["name"])
	}
	if got["opt"] != "REWROTE:uploads/d.png" {
		t.Errorf("nullable not rewritten: %v", got["opt"])
	}
	arr, ok := got["files"].([]any)
	if !ok || len(arr) != 2 {
		t.Fatalf("files array wrong: %#v", got["files"])
	}
	if arr[0] != "REWROTE:uploads/b.png" || arr[1] != "REWROTE:uploads/c.png" {
		t.Errorf("array items not rewritten: %v", arr)
	}
	if len(seen) != 4 {
		t.Errorf("expected 4 visits, got %d (%v)", len(seen), seen)
	}
}

func TestWalkSchemaNullableNullValue(t *testing.T) {
	// When the value is JSON null, the walker shouldn't call fn — leave
	// the null in place.
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"opt": map[string]any{"anyOf": []any{map[string]any{"type": "string", "format": "agent-file"}, map[string]any{"type": "null"}}},
		},
	}
	value := map[string]any{"opt": nil}
	called := false
	_, err := walkSchema(value, schema, "", func(format string, v any, ptr string) (any, *materializeError) {
		called = true
		return v, nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if called {
		t.Error("fn should not be called for null value")
	}
}
