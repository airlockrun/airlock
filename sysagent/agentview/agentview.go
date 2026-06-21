// Package agentview projects the public API protos down to a compact,
// LLM-friendly shape for the system agent's tool outputs. The proto stays the
// canonical API contract; this layer drops noise (timestamps) and bare UUIDs
// the LLM would only corrupt when echoing back — every identifier the agent
// needs to pass to another tool is a slug/email, exposed elsewhere on the object.
package agentview

import (
	"encoding/json"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// marshaler emits snake_case keys (matching the JSON the tools produced before
// this layer) and omits unset fields so the LLM sees only populated data.
var marshaler = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: false}

// Strip projects m to a JSON-ready map keyed by snake_case proto field names,
// with the named fields removed. It is the generic "drop noise" half of the
// agent view: callers list the timestamp/UUID fields that carry no value to the
// LLM (or that have a slug/email handle elsewhere on the object). Fields with no
// human handle (run/build ids) are simply not dropped.
func Strip(m proto.Message, drop ...string) map[string]any {
	raw, err := marshaler.Marshal(m)
	if err != nil {
		return map[string]any{"error": "marshal: " + err.Error()}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{"error": "unmarshal: " + err.Error()}
	}
	for _, k := range drop {
		delete(out, k)
	}
	return out
}

// StripEach maps Strip over a slice.
func StripEach[T proto.Message](ms []T, drop ...string) []map[string]any {
	out := make([]map[string]any, len(ms))
	for i, m := range ms {
		out[i] = Strip(m, drop...)
	}
	return out
}

// agentDrop is the field set an agent never needs from an AgentInfo: the raw
// UUID (the slug is the handle), provider UUIDs + model overrides (model config
// is a web/API concern, not an agent tool), the internal source ref, and
// timestamps.
var agentDrop = []string{
	"id", "created_at", "updated_at", "source_ref",
	"build_model", "exec_model",
	"build_provider_id", "exec_provider_id",
}

// Agent projects an AgentInfo (slug + status + running + your_access survive;
// UUIDs/timestamps/model config dropped).
func Agent(p *airlockv1.AgentInfo) map[string]any {
	return Strip(p, agentDrop...)
}

// Agents maps Agent over a slice.
func Agents(ps []*airlockv1.AgentInfo) []map[string]any {
	out := make([]map[string]any, len(ps))
	for i, p := range ps {
		out[i] = Agent(p)
	}
	return out
}
