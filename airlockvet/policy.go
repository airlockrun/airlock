package airlockvet

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

type policyAxisFact struct{ Axis string }

func (*policyAxisFact) AFact() {}

func (f *policyAxisFact) String() string { return f.Axis }

var Policy = &analysis.Analyzer{
	Name:      "policy",
	Doc:       "require complete Action declarations, valid permission axes, and tenant-axis helper arguments",
	FactTypes: []analysis.Fact{new(policyAxisFact)},
	Run:       runPolicy,
}

func runPolicy(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Path() == authzPkgPath {
		validatePolicy(pass)
		// The implementation validates dynamic helper arguments at runtime.
		return nil, nil
	}
	for _, file := range pass.Files {
		direct := map[*ast.Ident]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || isTestFile(pass, call.Pos()) {
				return true
			}
			var id *ast.Ident
			switch fun := ast.Unparen(call.Fun).(type) {
			case *ast.Ident:
				id = fun
			case *ast.SelectorExpr:
				id = fun.Sel
			}
			if id == nil {
				return true
			}
			fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
			if !ok || fn.Pkg() == nil || fn.Pkg().Path() != authzPkgPath {
				return true
			}
			if fn.Name() != "RequiredTenantRole" && fn.Name() != "AuthorizeOwnedResource" {
				return true
			}
			direct[id] = true
			var action *types.Const
			// Both helper contracts take their tenant-axis Action last.
			switch arg := ast.Unparen(call.Args[len(call.Args)-1]).(type) {
			case *ast.Ident:
				action, _ = pass.TypesInfo.Uses[arg].(*types.Const)
			case *ast.SelectorExpr:
				action, _ = pass.TypesInfo.Uses[arg.Sel].(*types.Const)
			}
			var fact policyAxisFact
			if action == nil || !pass.ImportObjectFact(action, &fact) || fact.Axis != "AxisTenant" {
				pass.Reportf(call.Pos(), "%s requires a declared tenant-axis Action constant", fn.Name())
			}
			return true
		})
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || direct[id] || isTestFile(pass, id.Pos()) {
				return true
			}
			fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
			if ok && fn.Pkg() != nil && fn.Pkg().Path() == authzPkgPath && (fn.Name() == "RequiredTenantRole" || fn.Name() == "AuthorizeOwnedResource") {
				pass.Reportf(id.Pos(), "%s must be called directly with a declared tenant-axis Action constant", fn.Name())
			}
			return true
		})
	}
	return nil, nil
}

func validatePolicy(pass *analysis.Pass) {
	actions := map[*types.Const]bool{}
	values := map[string]*types.Const{}
	for _, name := range pass.Pkg.Scope().Names() {
		obj, ok := pass.Pkg.Scope().Lookup(name).(*types.Const)
		if !ok || !isNamedType(obj.Type(), authzPkgPath, "Action") || isTestFile(pass, obj.Pos()) {
			continue
		}
		value := constant.StringVal(obj.Val())
		if value == "" || values[value] != nil {
			pass.Reportf(obj.Pos(), "Action %s must have a unique nonempty value", name)
		}
		values[value] = obj
		actions[obj] = false
	}
	found := false
	for _, file := range pass.Files {
		if isTestFile(pass, file.Pos()) {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "policy" || len(spec.Values) != 1 || pass.TypesInfo.Defs[spec.Names[0]] != pass.Pkg.Scope().Lookup("policy") {
				return true
			}
			literal, ok := spec.Values[0].(*ast.CompositeLit)
			if !ok {
				return true
			}
			m, ok := pass.TypesInfo.TypeOf(literal).(*types.Map)
			if !ok || !isNamedType(m.Key(), authzPkgPath, "Action") || !isNamedType(m.Elem(), authzPkgPath, "Requirement") {
				return true
			}
			found = true
			for _, elt := range literal.Elts {
				entry := elt.(*ast.KeyValueExpr)
				id, _ := entry.Key.(*ast.Ident)
				var action *types.Const
				if id != nil {
					action, _ = pass.TypesInfo.Uses[id].(*types.Const)
				}
				if _, declared := actions[action]; !declared {
					pass.Reportf(entry.Key.Pos(), "policy key must be a declared Action constant")
					continue
				}
				actions[action] = true
				req, ok := entry.Value.(*ast.CompositeLit)
				if !ok {
					pass.Reportf(entry.Value.Pos(), "policy requirement must be an explicit keyed literal")
					continue
				}
				fields := map[string]ast.Expr{}
				for _, elt := range req.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						fields[kv.Key.(*ast.Ident).Name] = kv.Value
					}
				}
				axis := ""
				if expr := fields["Axis"]; expr != nil {
					value := pass.TypesInfo.Types[expr].Value
					for _, name := range []string{"AxisAgent", "AxisTenant", "AxisIntegration", "AxisAuthenticated", "AxisApp"} {
						obj, _ := pass.Pkg.Scope().Lookup(name).(*types.Const)
						if obj != nil && value != nil && constant.Compare(value, token.EQL, obj.Val()) {
							axis = name
						}
					}
				}
				valid := len(fields) == len(req.Elts)
				switch axis {
				case "AxisAgent", "AxisIntegration":
					valid = valid && len(fields) == 2 && validPolicyLevel(pass, fields["Agent"], "public", "user", "admin")
				case "AxisTenant":
					valid = valid && len(fields) == 2 && validPolicyLevel(pass, fields["Tenant"], "user", "manager", "admin")
				case "AxisAuthenticated", "AxisApp":
					valid = valid && len(fields) == 1
				default:
					valid = false
				}
				if !valid {
					pass.Reportf(req.Pos(), "invalid policy requirement: explicit valid Axis and only its required access field are mandatory")
				} else {
					pass.ExportObjectFact(action, &policyAxisFact{Axis: axis})
				}
			}
			return false
		})
	}
	if !found {
		pass.Reportf(pass.Files[0].Pos(), "authz requires an explicit policy map[Action]Requirement declaration")
	}
	for action, covered := range actions {
		if !covered {
			pass.Reportf(action.Pos(), "Action %s is missing from policy", action.Name())
		}
	}
}

func validPolicyLevel(pass *analysis.Pass, expr ast.Expr, levels ...string) bool {
	if expr == nil {
		return false
	}
	value := pass.TypesInfo.Types[expr].Value
	if value == nil || value.Kind() != constant.String {
		return false
	}
	for _, level := range levels {
		if constant.StringVal(value) == level {
			return true
		}
	}
	return false
}
