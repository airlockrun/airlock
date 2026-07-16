package builder

import (
	"bytes"
	"strings"
	"testing"
)

func TestAgentBuilderPromptUsesSDKBuildCommand(t *testing.T) {
	var prompt bytes.Buffer
	if err := builderTmpl.Execute(&prompt, BuilderPromptData{}); err != nil {
		t.Fatalf("render builder prompt: %v", err)
	}
	if !strings.Contains(prompt.String(), "go tool air build") {
		t.Fatal("builder prompt does not use the SDK-owned build command")
	}
	if strings.Contains(prompt.String(), "tailwindcss -i styles/app.css") {
		t.Fatal("builder prompt contains a direct Tailwind build command")
	}
	for _, want := range []string{
		"do not delete them as cleanup",
		"source commits ignore generated copies",
		"sqlc runs automatically",
		"`internal/db/doc.go` is preserved",
		"go test -p=1 -count=1 ./...",
		"direct constructor injection",
		"`newAgent` is the composition root",
		"must never import a package that imports that domain",
		"never use package-level globals or service locators",
		"go tool air integrations list",
		"go tool air mcp probe <url>",
		"Never run `go tool air deploy`",
	} {
		if !strings.Contains(prompt.String(), want) {
			t.Errorf("builder prompt missing generated-file rule %q", want)
		}
	}
	for _, stale := range []string{"Agent.Deps", "GetDeps[", "mcp_probe"} {
		if strings.Contains(prompt.String(), stale) {
			t.Errorf("builder prompt contains stale dependency API %q", stale)
		}
	}
}
