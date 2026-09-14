package airlockvet

import (
	"go/token"
	"strings"

	"golang.org/x/tools/go/analysis"
)

var suppressionTags = map[string]bool{
	"allow-dbq": true, "allow-inline-role": true,
	"allow-writejson": true, "allow-agentwire": true,
}

// Suppressions validates directives independently of the rule's package scope.
var Suppressions = &analysis.Analyzer{
	Name: "suppressions",
	Doc:  "require exact airlockvet suppression tags and nonempty reasons",
	Run: func(pass *analysis.Pass) (any, error) {
		for _, f := range pass.Files {
			for _, group := range f.Comments {
				for _, c := range group.List {
					text := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(c.Text, "//"), "/*"))
					if !strings.HasPrefix(text, "airlockvet:") {
						continue
					}
					if _, ok := parseMarker(c.Text); !ok {
						pass.Reportf(c.Pos(), "invalid airlockvet suppression: require // airlockvet:<known-tag> reason: <nonempty reason>")
					}
				}
			}
		}
		return nil, nil
	},
}

func parseMarker(text string) (string, bool) {
	if !strings.HasPrefix(text, "//") {
		return "", false
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "//"))
	if !strings.HasPrefix(text, "airlockvet:") {
		return "", false
	}
	tag, rest, ok := strings.Cut(strings.TrimPrefix(text, "airlockvet:"), " ")
	reason, hasReason := strings.CutPrefix(strings.TrimSpace(rest), "reason:")
	return tag, ok && suppressionTags[tag] && hasReason && strings.TrimSpace(reason) != ""
}

type allowMarkers struct {
	pass *analysis.Pass
	tag  string
	hits map[allowKey]*allowMarker
}

type allowMarker struct {
	pos  token.Pos
	used bool
}

type allowKey struct {
	file string
	line int
}

func collectAllowMarkers(pass *analysis.Pass, tag string) *allowMarkers {
	m := &allowMarkers{pass: pass, tag: tag, hits: make(map[allowKey]*allowMarker)}
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if parsed, ok := parseMarker(c.Text); !ok || parsed != tag || isTestFile(pass, c.Pos()) {
					continue
				}
				pos := pass.Fset.Position(c.Pos())
				m.hits[allowKey{pos.Filename, pos.Line}] = &allowMarker{pos: c.Pos()}
			}
		}
	}
	return m
}

// A directive applies only to its own line or the immediately following line.
func (m *allowMarkers) allowed(pos token.Pos) bool {
	p := m.pass.Fset.Position(pos)
	for _, line := range []int{p.Line, p.Line - 1} {
		if marker, ok := m.hits[allowKey{p.Filename, line}]; ok {
			marker.used = true
			return true
		}
	}
	return false
}

func (m *allowMarkers) reportUnused() {
	for _, marker := range m.hits {
		if !marker.used {
			m.pass.Reportf(marker.pos, "unused airlockvet:%s suppression", m.tag)
		}
	}
}
