package sysagent

import (
	"bytes"
	_ "embed"
	"sort"
	"strings"
	"text/template"

	"github.com/airlockrun/goai/tool"
)

//go:embed prompt.tmpl
var promptTmplSrc string

var promptTmpl = template.Must(template.New("sysagent").Parse(promptTmplSrc))

// promptEnv is the per-turn <env> context. Every field is set explicitly by
// the caller (never inferred); an empty field is omitted from the block.
type promptEnv struct {
	Date         string
	Platform     string
	UserName     string
	UserEmail    string
	Conversation string
	WebURL       string // base URL of the airlock web UI (no trailing slash)
}

type sysToolInfo struct {
	Name string
	Desc string
}

type sysPromptData struct {
	Env   promptEnv
	Tools []sysToolInfo
}

// SystemPrompt renders the sysagent chat system prompt: the conventions
// preamble, the per-turn <env> block, and a tool catalogue generated from the
// registered (tenant-filtered) tool set so it can't drift from the actual
// Execute surface. Only the first description line is shown — the full schema
// reaches the model via the tool envelope.
func SystemPrompt(env promptEnv, availableTools tool.Set) string {
	names := make([]string, 0, len(availableTools))
	for name := range availableTools {
		names = append(names, name)
	}
	sort.Strings(names)
	tools := make([]sysToolInfo, 0, len(names))
	for _, n := range names {
		desc := availableTools[n].Description
		if i := strings.IndexByte(desc, '\n'); i > 0 {
			desc = desc[:i]
		}
		tools = append(tools, sysToolInfo{Name: n, Desc: desc})
	}

	var buf bytes.Buffer
	// Render errors here are template bugs, not user input — panic loud so the
	// operator notices in test rather than shipping a broken prompt.
	if err := promptTmpl.Execute(&buf, sysPromptData{Env: env, Tools: tools}); err != nil {
		panic("sysagent: render system prompt: " + err.Error())
	}
	return buf.String()
}
