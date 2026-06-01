package convert

import "testing"

// TestPendingSystemToolFromCheckpoint verifies the LLM's pending tool
// call (stored as the sol.SuspensionContext JSON blob on the
// conversation row) decodes into the wire shape the confirmation UI
// binds to. The frontend's ToolBadge and Approve/Deny card rely on
// call_id + tool_name + args_json being populated; a regression here
// renders the confirmation card empty.
func TestPendingSystemToolFromCheckpoint(t *testing.T) {
	t.Run("first pending call extracted", func(t *testing.T) {
		blob := []byte(`{
			"pendingToolCalls": [
				{"id": "call-1", "name": "delete_agent", "input": {"agent": "test-bot"}},
				{"id": "call-2", "name": "trigger_agent_upgrade", "input": {"agent": "other"}}
			]
		}`)
		got := PendingSystemToolFromCheckpoint(blob)
		if got == nil {
			t.Fatal("expected pending tool, got nil")
		}
		if got.CallId != "call-1" {
			t.Errorf("CallId: got %q want call-1", got.CallId)
		}
		if got.ToolName != "delete_agent" {
			t.Errorf("ToolName: got %q want delete_agent", got.ToolName)
		}
		if got.ArgsJson == "" {
			t.Errorf("ArgsJson should carry the input JSON, got empty")
		}
	})

	t.Run("empty checkpoint returns nil", func(t *testing.T) {
		if got := PendingSystemToolFromCheckpoint(nil); got != nil {
			t.Errorf("nil blob should return nil, got %+v", got)
		}
		if got := PendingSystemToolFromCheckpoint([]byte(`{"pendingToolCalls": []}`)); got != nil {
			t.Errorf("empty list should return nil, got %+v", got)
		}
	})

	t.Run("malformed JSON returns nil instead of panicking", func(t *testing.T) {
		if got := PendingSystemToolFromCheckpoint([]byte(`not json`)); got != nil {
			t.Errorf("malformed JSON should return nil, got %+v", got)
		}
	})
}
