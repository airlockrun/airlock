package airlockvet

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Declared as a var so wire-check tests can select a fixture package.
var apiPkgPath = "github.com/airlockrun/airlock/api"

// dbqPkgPath identifies the receiver type the NoDBQ analyzer flags.
const dbqPkgPath = "github.com/airlockrun/airlock/db/dbq"

// NoDBQ flags dbq query method references at transport boundaries.
// Handler code that needs database access must go through a
// service/{domain} method so authz.Authorize gates the call.
//
// Opt-out per call: place `// airlockvet:allow-dbq reason: <why>` on
// the same line or the line above the offending expression.
var NoDBQ = &analysis.Analyzer{
	Name:     "nodbq",
	Doc:      "report direct dbq query method references in transport packages; call services instead",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      runNoDBQ,
}

func runNoDBQ(pass *analysis.Pass) (any, error) {
	allow := collectAllowMarkers(pass, "allow-dbq")
	defer allow.reportUnused()
	if !transportPackage(pass.Pkg.Path()) {
		return nil, nil
	}
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	filter := []ast.Node{(*ast.Ident)(nil)}

	insp.Preorder(filter, func(n ast.Node) {
		id := n.(*ast.Ident)
		fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
		if !ok || fn.Pkg() == nil || fn.Pkg().Path() != dbqPkgPath {
			return
		}
		sig := fn.Type().(*types.Signature)
		if sig.Recv() == nil || (!isNamedType(sig.Recv().Type(), dbqPkgPath, "Queries") && !isNamedType(sig.Recv().Type(), dbqPkgPath, "Querier")) {
			return
		}
		if isTestFile(pass, id.Pos()) || allow.allowed(id.Pos()) {
			return
		}
		pass.Reportf(id.Pos(), "direct dbq.Queries.%s reference in transport: route through service/{domain} (or annotate narrow plumbing with // airlockvet:allow-dbq reason: <why>)", id.Name)
	})
	return nil, nil
}

func isNamedType(t types.Type, pkg, name string) bool {
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == pkg && obj.Name() == name
}

func transportPackage(pkg string) bool {
	for _, root := range []string{apiPkgPath, agentapiPkgPath, corePkgPath + "/hostapi", corePkgPath + "/sysagent", enterprisePkgPath + "/api", enterprisePkgPath + "/agentapi", enterprisePkgPath + "/hostapi"} {
		if withinPackage(pkg, root) {
			return true
		}
	}
	return false
}

// isTestFile reports whether pos lives in a _test.go file. Tests
// legitimately seed fixtures via dbq.
func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
