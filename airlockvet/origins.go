package airlockvet

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/analysis"
)

const (
	executionPkgPath     = corePkgPath + "/service/execution"
	systemchatPkgPath    = corePkgPath + "/service/systemchat"
	appruntimePkgPath    = corePkgPath + "/service/appruntime"
	executionTestPkgPath = executionPkgPath + "/executiontest"
	wirePkgPath          = "github.com/airlockrun/agentsdk/wire"
)

// Origins protects credential restoration and the writes that turn untrusted
// coordinates into durable authority. Package permissions are exact, not trees.
var Origins = &analysis.Analyzer{
	Name: "origins",
	Doc:  "restrict principal construction, identity restoration, runtime identity projection, and durable origin writers",
	Run:  runOrigins,
}

func runOrigins(pass *analysis.Pass) (any, error) {
	pkg := pass.Pkg.Path()
	if pkg == authPkgPath {
		if obj := pass.Pkg.Scope().Lookup("Identity"); obj != nil {
			if fields, ok := obj.Type().Underlying().(*types.Struct); ok {
				for i := 0; i < fields.NumFields(); i++ {
					if field := fields.Field(i); field.Exported() {
						pass.Reportf(field.Pos(), "auth.Identity fields must remain private")
					}
				}
			}
		}
		for _, obj := range pass.TypesInfo.Defs {
			if obj == nil || !obj.Exported() || isTestFile(pass, obj.Pos()) {
				continue
			}
			switch obj.(type) {
			case *types.Func:
			case *types.Var:
				if obj.Parent() != pass.Pkg.Scope() {
					continue
				}
			default:
				continue
			}
			sig, ok := obj.Type().Underlying().(*types.Signature)
			if !ok || sig.Recv() != nil && obj.Name() == "Identity" && isNamedType(sig.Recv().Type(), authPkgPath, "Claims") {
				continue
			}
			for i := 0; i < sig.Results().Len(); i++ {
				if _, name := authorityType(sig.Results().At(i).Type()); name == "Identity" {
					pass.Reportf(obj.Pos(), "auth.Identity constructors must remain private; restore only by admitted run ID")
				}
			}
		}
	}
	for _, file := range pass.Files {
		if isTestFile(pass, file.Pos()) {
			continue
		}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if path == executionTestPkgPath {
				pass.Reportf(imp.Pos(), "executiontest may only be imported by _test.go files")
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				fn, ok := pass.TypesInfo.Uses[n].(*types.Func)
				if !ok || fn.Pkg() == nil {
					break
				}
				allowed, restricted := false, false
				switch fn.Pkg().Path() {
				case authPkgPath:
					switch fn.Name() {
					case "RestoreRunIdentity":
						allowed, restricted = pkg == authPkgPath || pkg == executionPkgPath, true
					case "RestoreSystemRunIdentity":
						allowed, restricted = pkg == authPkgPath || pkg == systemchatPkgPath, true
					}
				case authzPkgPath:
					if fn.Name() == "AppRunPrincipal" {
						allowed, restricted = pkg == authzPkgPath || pkg == executionPkgPath, true
					}
					if fn.Name() == "UserPrincipal" {
						// These services restore durable job or single-use OAuth authority;
						// transport admission must preserve verified Claims.Identity.
						allowed = pkg == authzPkgPath || pkg == executionPkgPath || pkg == corePkgPath+"/service/connections" || pkg == corePkgPath+"/service/inboundoauth"
						restricted = true
					}
				case dbqPkgPath:
					sig := fn.Type().(*types.Signature)
					if sig.Recv() == nil || (!isNamedType(sig.Recv().Type(), dbqPkgPath, "Queries") && !isNamedType(sig.Recv().Type(), dbqPkgPath, "Querier")) {
						break
					}
					switch fn.Name() {
					case "CreateExecutionOrigin", "InsertAgentJobFromCron", "CreateExecutionInvocation":
						allowed, restricted = pkg == executionPkgPath || pkg == executionTestPkgPath, true
					case "CreateRun":
						allowed, restricted = pkg == executionPkgPath || pkg == appruntimePkgPath || pkg == executionTestPkgPath, true
					case "CreateSystemRun", "CreateSystemRunOrigin", "CreateAsyncChatOrigin":
						allowed, restricted = pkg == systemchatPkgPath, true
					case "AdmitAppRunGeneration":
						allowed, restricted = pkg == appruntimePkgPath, true
					case "CreateAgentTaskSession", "CreateAgentTaskCall", "ClaimAgentTaskCall", "RecordAgentTaskClaim":
						allowed, restricted = pkg == corePkgPath+"/service/agentruns", true
					case "RecordAgentTaskUsage", "ChargeAgentTaskBudget":
						allowed, restricted = pkg == executionPkgPath, true
					}
				}
				if restricted && !allowed {
					pass.Reportf(n.Pos(), "%s.%s is restricted to its designated credential/origin service", fn.Pkg().Name(), fn.Name())
				}
			case *ast.CompositeLit:
				owner, name := authorityType(pass.TypesInfo.TypeOf(n))
				if owner != "" && pkg != owner && (len(n.Elts) != 0 || name == "Identity") {
					pass.Reportf(n.Pos(), "%s construction belongs in %s; retain verified admission instead of fabricating authority", name, owner)
				}
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					reportAuthorityFieldWrite(pass, lhs)
				}
			case *ast.IncDecStmt:
				reportAuthorityFieldWrite(pass, n.X)
			case *ast.RangeStmt:
				if n.Key != nil {
					reportAuthorityFieldWrite(pass, n.Key)
				}
				if n.Value != nil {
					reportAuthorityFieldWrite(pass, n.Value)
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					// Taking a field address would permit mutation through a local alias.
					reportAuthorityFieldWrite(pass, n.X)
				}
			case *ast.CallExpr:
				if pass.TypesInfo.Types[n.Fun].IsType() {
					owner, name := authorityType(pass.TypesInfo.TypeOf(n))
					if owner != "" && pkg != owner {
						pass.Reportf(n.Pos(), "conversion to %s belongs in %s", name, owner)
					}
				}
				if id, ok := n.Fun.(*ast.Ident); ok {
					if builtin, ok := pass.TypesInfo.Uses[id].(*types.Builtin); ok && builtin.Name() == "new" {
						if owner, name := authorityType(pass.TypesInfo.TypeOf(n)); name == "Identity" && pkg != owner {
							pass.Reportf(n.Pos(), "Identity construction belongs in auth")
						}
					}
				}
				fn := calledFunction(pass, n)
				if fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "encoding/json" && (fn.Name() == "Unmarshal" || fn.Name() == "Decode") && len(n.Args) > 0 {
					if owner, name := authorityType(pass.TypesInfo.TypeOf(n.Args[len(n.Args)-1])); owner != "" {
						pass.Reportf(n.Pos(), "cannot decode payload into %s authority; resolve verified admission", name)
					}
				}
			}
			return true
		})
	}
	return nil, nil
}

// Empty Principal/runtime values remain usable as error returns. Their populated
// forms and field writes have one owner, including in otherwise trusted services.
func authorityType(t types.Type) (owner, name string) {
	if t == nil {
		return "", ""
	}
	for {
		t = types.Unalias(t)
		ptr, ok := t.(*types.Pointer)
		if !ok {
			break
		}
		t = ptr.Elem()
	}
	for _, candidate := range []struct{ pkg, name, owner string }{
		{authPkgPath, "Identity", authPkgPath},
		{authzPkgPath, "Principal", authzPkgPath},
		{wirePkgPath, "RuntimeContext", executionPkgPath},
		{wirePkgPath, "Caller", executionPkgPath},
		{wirePkgPath, "CallerUser", executionPkgPath},
		{wirePkgPath, "CallerOrigin", executionPkgPath},
		{wirePkgPath, "RuntimeJobContext", executionPkgPath},
		{wirePkgPath, "RuntimeAgentDefinition", executionPkgPath},
	} {
		if isNamedType(t, candidate.pkg, candidate.name) {
			return candidate.owner, candidate.name
		}
	}
	return "", ""
}

func reportAuthorityFieldWrite(pass *analysis.Pass, expr ast.Expr) {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return
	}
	selection := pass.TypesInfo.Selections[sel]
	if selection == nil || selection.Kind() != types.FieldVal {
		return
	}
	// Follow embedded fields to the type that actually declares the selected field.
	t := selection.Recv()
	for _, index := range selection.Index() {
		owner, name := authorityType(t)
		if owner != "" && pass.Pkg.Path() != owner {
			pass.Reportf(expr.Pos(), "%s field mutation belongs in %s", name, owner)
			return
		}
		t = types.Unalias(t)
		if ptr, ok := t.(*types.Pointer); ok {
			t = ptr.Elem()
		}
		t = t.Underlying().(*types.Struct).Field(index).Type()
	}
}
