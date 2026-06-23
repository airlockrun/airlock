package builder

import (
	"strings"
	"testing"
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
