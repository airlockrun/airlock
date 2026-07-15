package builder

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/airlockrun/goai/tool"
)

func TestStripMarkdown(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // compared after TrimSpace
	}{
		{"heading", "# Summary\nDid the thing.", "Summary\nDid the thing."},
		{"bold", "Build **complete** now.", "Build complete now."},
		{"italic", "Build *complete* now.", "Build complete now."},
		{"inline code", "Ran `go test` ok.", "Ran go test ok."},
		{"link", "See [the docs](https://x.dev/y).", "See the docs."},
		{"image dropped", "Look ![diagram](u.png)here.", "Look here."},
		{"star bullets", "Changes:\n* one\n* two", "Changes:\n- one\n- two"},
		{"snake_case preserved", "Set my_var_name and __dunder__.", "Set my_var_name and __dunder__."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.TrimSpace(stripMarkdown(tt.in)); got != tt.want {
				t.Errorf("stripMarkdown(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestStripMarkdownCodeFence(t *testing.T) {
	got := stripMarkdown("Done:\n```go\nfmt.Println()\n```\nShipped.")
	if strings.Contains(got, "```") {
		t.Errorf("fence markers survived: %q", got)
	}
	if !strings.Contains(got, "fmt.Println()") {
		t.Errorf("fenced content dropped: %q", got)
	}
}

func TestCodegenCommitMessageStripsMarkdown(t *testing.T) {
	plan := BuildPlan{Kind: "build", Instruction: "Add a kanban board"}
	msg := codegenCommitMessage(plan, "agent-123", "## Summary\n\nBuilt a **kanban** with `htmx` and [daisyUI](https://daisyui.com).")

	if strings.Contains(msg, "`") || strings.Contains(msg, "**") || strings.Contains(msg, "#") {
		t.Errorf("commit message retains markdown:\n%s", msg)
	}
	if !strings.HasPrefix(msg, "Add a kanban board") {
		t.Errorf("subject should be the instruction's first line; got:\n%s", msg)
	}
	if !strings.Contains(msg, "daisyUI") {
		t.Errorf("link text was dropped: %s", msg)
	}
}

func TestVerifyGeneratedCodeRunsSDKBuild(t *testing.T) {
	executor := &verificationExecutor{
		responses: []tool.Response{
			{Output: verificationExitMarker + "0\nbuild and tests ok\n"},
		},
	}
	var logs []string
	if err := verifyGeneratedCode(context.Background(), executor, func(line string) {
		logs = append(logs, line)
	}); err != nil {
		t.Fatalf("verifyGeneratedCode: %v", err)
	}

	want := []string{"go tool air build"}
	if len(executor.commands) != len(want) {
		t.Fatalf("commands = %q, want %q", executor.commands, want)
	}
	for i := range want {
		if executor.commands[i] != want[i] {
			t.Errorf("command %d = %q, want %q", i, executor.commands[i], want[i])
		}
	}
	joined := strings.Join(logs, "\n")
	for _, text := range []string{"[verify] go tool air build", "[verify] build and tests ok"} {
		if !strings.Contains(joined, text) {
			t.Errorf("verification logs missing %q:\n%s", text, joined)
		}
	}
}

func TestVerifyGeneratedCodeStopsAfterBuildFailure(t *testing.T) {
	executor := &verificationExecutor{responses: []tool.Response{{
		Output: verificationExitMarker + "1\n./main.go:12: undefined: missing\nExit code: exit status 1",
	}}}
	var logs []string
	err := verifyGeneratedCode(context.Background(), executor, func(line string) {
		logs = append(logs, line)
	})
	if err == nil {
		t.Fatal("verifyGeneratedCode succeeded, want failure")
	}
	if len(executor.commands) != 1 || executor.commands[0] != "go tool air build" {
		t.Fatalf("commands = %q, want only SDK build", executor.commands)
	}
	for _, text := range []string{"go tool air build", "./main.go:12: undefined: missing"} {
		if !strings.Contains(err.Error(), text) {
			t.Errorf("error missing %q: %v", text, err)
		}
	}
	if !strings.Contains(strings.Join(logs, "\n"), "undefined: missing") {
		t.Errorf("verification logs lack compiler diagnostic: %q", logs)
	}
}

type verificationExecutor struct {
	responses []tool.Response
	commands  []string
}

func (e *verificationExecutor) Execute(_ context.Context, req tool.Request) (tool.Response, error) {
	var input struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(req.Input, &input); err != nil {
		return tool.Response{}, err
	}
	for _, command := range []string{"go tool air build"} {
		if strings.Contains(input.Command, command) {
			e.commands = append(e.commands, command)
			break
		}
	}
	response := e.responses[0]
	e.responses = e.responses[1:]
	return response, nil
}

func (*verificationExecutor) Tools() []tool.Info { return nil }
