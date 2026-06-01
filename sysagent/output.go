package sysagent

import (
	"encoding/json"
	"fmt"

	"github.com/airlockrun/goai/tool"
)

// MaxToolOutputBytes caps every tool result (success and error) at
// 8 KiB. Tools that hand back larger payloads get truncated with a
// "[truncated: total=N bytes; refine query or paginate]" suffix, so
// one runaway list_runs call can't blow through the LLM's context
// budget. Sized to match the agentsdk JS-binding spill threshold so
// the LLM sees one consistent "8 KiB-ish" budget across surfaces.
const MaxToolOutputBytes = 8 * 1024

// truncationSuffixFormat reserves a small footer at the end of an
// over-cap output. Printf-formatted with the true byte count so the
// LLM can decide whether to paginate.
const truncationSuffixFormat = "\n… [truncated: total=%d bytes; refine query or paginate]"

// okResult JSON-marshals v with 2-space indentation and returns a
// tool.Result capped at MaxToolOutputBytes. Service return structs
// (with json tags) ARE the schema-of-record — new fields appear in
// tool output automatically; no hand-written renderer to keep in
// sync.
//
// Indented form matches the shape agent chat returns from run_js, so
// ToolBadge's collapsed-preview line-clipping behaves the same on
// both surfaces and the LLM sees a uniformly readable layout when it
// quotes JSON back. Costs a few extra tokens per call (whitespace)
// but well within the 8 KiB cap.
//
// On marshal failure (shouldn't happen for service return types) the
// error path runs through errResult, so the LLM still sees structured
// "Error: …" text rather than empty output.
func okResult(v any) (tool.Result, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errResult(fmt.Errorf("marshal tool result: %w", err)), nil
	}
	return tool.Result{Output: capOutput(string(b))}, nil
}

// errResult wraps a (typically service-layer sentinel) error in the
// standard "Error: <msg>" envelope the LLM is taught to interpret in
// the system prompt. Always returned as the tool.Result with a nil Go
// error: from the executor's view this is a SUCCESSFUL invocation that
// happens to be a refusal — feeding it back as a normal tool result
// lets the LLM apologise/redirect rather than retrying the call.
//
// Capped at MaxToolOutputBytes for symmetry with okResult.
func errResult(err error) tool.Result {
	if err == nil {
		return tool.Result{Output: "Error: unknown"}
	}
	return tool.Result{Output: capOutput("Error: " + err.Error())}
}

// capOutput truncates s to MaxToolOutputBytes, appending a footer
// noting the original size when truncation happens.
func capOutput(s string) string {
	if len(s) <= MaxToolOutputBytes {
		return s
	}
	total := len(s)
	suffix := fmt.Sprintf(truncationSuffixFormat, total)
	keep := MaxToolOutputBytes - len(suffix)
	if keep < 0 {
		// Pathological — suffix alone overflows the cap. Hand back
		// just the suffix so the LLM at least sees "something was
		// truncated"; should never happen in practice (cap >> suffix).
		return suffix
	}
	return s[:keep] + suffix
}
