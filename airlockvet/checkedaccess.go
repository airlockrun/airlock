package airlockvet

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

var CheckedAccess = &analysis.Analyzer{
	Name: "checkedaccess",
	Doc:  "require error-returning effective access lookups and reject explicitly discarded lookup errors",
	Run: func(pass *analysis.Pass) (any, error) {
		for _, file := range pass.Files {
			if isTestFile(pass, file.Pos()) {
				continue
			}
			direct := map[*ast.Ident]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := ast.Unparen(call.Fun).(type) {
				case *ast.SelectorExpr:
					direct[fun.Sel] = true
				case *ast.Ident:
					direct[fun] = true
				}
				return true
			})
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.Ident:
					fn, ok := pass.TypesInfo.Uses[n].(*types.Func)
					if ok && fn.Pkg() != nil && fn.Pkg().Path() == authzPkgPath && (fn.Name() == "EffectiveAgentAccess" || fn.Name() == "EffectiveAgentAccessGranted") {
						pass.Reportf(n.Pos(), "authz.%s discards lookup errors: use EffectiveAgentAccessChecked and propagate its error", fn.Name())
					}
					if ok && fn.Pkg() != nil && fn.Pkg().Path() == authzPkgPath && fn.Name() == "EffectiveAgentAccessChecked" && !direct[n] {
						pass.Reportf(n.Pos(), "EffectiveAgentAccessChecked must be called directly so its error can be checked")
					}
				case *ast.AssignStmt:
					if len(n.Rhs) == 1 && len(n.Lhs) == 3 {
						if id, ok := n.Lhs[2].(*ast.Ident); ok && id.Name == "_" && checkedAccessCall(pass, n.Rhs[0]) {
							pass.Reportf(id.Pos(), "EffectiveAgentAccessChecked error must not be discarded")
						}
					}
				case *ast.ValueSpec:
					if len(n.Values) == 1 && len(n.Names) == 3 && n.Names[2].Name == "_" && checkedAccessCall(pass, n.Values[0]) {
						pass.Reportf(n.Names[2].Pos(), "EffectiveAgentAccessChecked error must not be discarded")
					}
				case *ast.ExprStmt:
					if checkedAccessCall(pass, n.X) {
						pass.Reportf(n.Pos(), "EffectiveAgentAccessChecked error must not be discarded")
					}
				case *ast.GoStmt:
					if checkedAccessCall(pass, n.Call) {
						pass.Reportf(n.Pos(), "EffectiveAgentAccessChecked error must not be discarded")
					}
				case *ast.DeferStmt:
					if checkedAccessCall(pass, n.Call) {
						pass.Reportf(n.Pos(), "EffectiveAgentAccessChecked error must not be discarded")
					}
				}
				return true
			})
		}
		return nil, nil
	},
}

func checkedAccessCall(pass *analysis.Pass, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	fn := calledFunction(pass, call)
	return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == authzPkgPath && fn.Name() == "EffectiveAgentAccessChecked"
}

func calledFunction(pass *analysis.Pass, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch expr := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = expr
	case *ast.SelectorExpr:
		id = expr.Sel
	}
	if id == nil {
		return nil
	}
	fn, _ := pass.TypesInfo.Uses[id].(*types.Func)
	return fn
}
