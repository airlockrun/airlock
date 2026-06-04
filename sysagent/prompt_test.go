package sysagent

import (
	"strings"
	"testing"

	"github.com/airlockrun/goai/tool"
)

func TestSystemPromptTemplate(t *testing.T) {
	tools := tool.Set{
		"whoami": tool.New("whoami").Description("Show your access.\nsecond line ignored").Build(),
	}

	// Telegram: env block carries platform + user + the no-tables note; the
	// preamble and tool catalogue still render.
	out := SystemPrompt(promptEnv{Date: "2026-06-04", Platform: "telegram", UserName: "Jane Doe", UserEmail: "jane@example.com", Conversation: "c1"}, tools)
	for _, want := range []string{
		"You are the airlock system agent", // preamble preserved
		"## Conventions",                   // preamble preserved
		"## Available tools",               // catalogue header
		"- `whoami` — Show your access.",   // tool, first desc line only
		"<env>\nDate: 2026-06-04\nPlatform: telegram\nUser: Jane Doe <jane@example.com>\nConversation: c1\nRendering: this channel doesn't render Markdown tables",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("prompt missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "second line ignored") {
		t.Fatal("tool catalogue should keep only the first description line")
	}

	// Web: no rendering note.
	web := SystemPrompt(promptEnv{Date: "2026-06-04", Platform: "web", UserName: "Jane Doe"}, tools)
	if strings.Contains(web, "Rendering:") {
		t.Fatalf("web prompt should not carry a rendering note:\n%s", web)
	}
	if !strings.Contains(web, "<env>\nDate: 2026-06-04\nPlatform: web\nUser: Jane Doe\n</env>") {
		t.Fatalf("web env block wrong:\n%s", web)
	}
}
