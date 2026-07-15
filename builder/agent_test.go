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
}
