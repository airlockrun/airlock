package airlockvet

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const authPkgPath = corePkgPath + "/auth"

var NoInlineRole = &analysis.Analyzer{
	Name:     "noinlinerole",
	Doc:      "report inline tenant role constants and comparators outside the policy implementation",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      runNoInlineRole,
}

func runNoInlineRole(pass *analysis.Pass) (any, error) {
	allow := collectAllowMarkers(pass, "allow-inline-role")
	defer allow.reportUnused()
	pkg := pass.Pkg.Path()
	if pkg == authPkgPath || pkg == authzPkgPath {
		return nil, nil
	}
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	insp.Preorder([]ast.Node{(*ast.Ident)(nil)}, func(n ast.Node) {
		id := n.(*ast.Ident)
		obj := pass.TypesInfo.Uses[id]
		if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != authPkgPath || isTestFile(pass, id.Pos()) {
			return
		}
		switch obj := obj.(type) {
		case *types.Const:
			// Enum serialization and dedicated fixture construction contain no gates.
			if pkg == corePkgPath+"/convert" || pkg == corePkgPath+"/apitest" || !isNamedType(obj.Type(), authPkgPath, "Role") {
				return
			}
		case *types.Func:
			sig := obj.Type().(*types.Signature)
			if obj.Name() != "RequireTenantRole" && (obj.Name() != "AtLeast" || sig.Recv() == nil || !isNamedType(sig.Recv().Type(), authPkgPath, "Role")) {
				return
			}
		default:
			return
		}
		if !allow.allowed(id.Pos()) {
			pass.Reportf(id.Pos(), "inline reference to %s outside authz/: route the gate through authz.Authorize with a declared Action", obj.Name())
		}
	})
	return nil, nil
}
