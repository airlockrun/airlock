package airlockvet

import (
	"go/token"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// allowMarkers indexes opt-out comments by (filename, line) for one pass.
// A marker on the violation's own line OR the immediately preceding line
// suppresses the diagnostic.
type allowMarkers struct {
	fset *token.FileSet
	hits map[allowKey]struct{}
}

type allowKey struct {
	file string
	line int
}

// collectAllowMarkers scans every file in the pass for comments matching
// "airlockvet:" + tag and records their line numbers. Each call returns a
// fresh marker set keyed to the supplied tag (e.g. "allow-dbq").
func collectAllowMarkers(pass *analysis.Pass, tag string) *allowMarkers {
	m := &allowMarkers{fset: pass.Fset, hits: make(map[allowKey]struct{})}
	needle := "airlockvet:" + tag
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if !strings.Contains(c.Text, needle) {
					continue
				}
				pos := pass.Fset.Position(c.Pos())
				m.hits[allowKey{pos.Filename, pos.Line}] = struct{}{}
			}
		}
	}
	return m
}

// allowed reports whether the diagnostic at pos is suppressed by a marker
// on the same line or the line directly above it.
func (m *allowMarkers) allowed(pos token.Pos) bool {
	p := m.fset.Position(pos)
	if _, ok := m.hits[allowKey{p.Filename, p.Line}]; ok {
		return true
	}
	_, ok := m.hits[allowKey{p.Filename, p.Line - 1}]
	return ok
}
